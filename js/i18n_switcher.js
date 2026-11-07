/**
 * Bilingual i18n Switcher Module (zh-TW / en-US)
 * Agent: bilingual_i18n_specialist
 * Strictly Traditional Chinese (zh-TW) and Commercial English (en-US)
 */
(function () {
  const STORAGE_KEY = 'tcstorefront_lang';
  const SUPPORTED_LANGS = ['zh-TW', 'en-US'];

  // Embedded fallback dictionaries in case local file:// protocol blocks fetch
  let loadedDictionaries = {
    'zh-TW': null,
    'en-US': null
  };

  let currentLang = localStorage.getItem(STORAGE_KEY);
  if (!SUPPORTED_LANGS.includes(currentLang)) {
    currentLang = 'zh-TW';
  }

  async function fetchLocaleJson(lang) {
    if (loadedDictionaries[lang]) return loadedDictionaries[lang];
    try {
      const res = await fetch(`./locales/${lang}.json`, { cache: 'no-cache' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      loadedDictionaries[lang] = data;
      return data;
    } catch (err) {
      if (window.__FALLBACK_LOCALES__ && window.__FALLBACK_LOCALES__[lang]) {
        loadedDictionaries[lang] = window.__FALLBACK_LOCALES__[lang];
        return loadedDictionaries[lang];
      }
      console.error(`[i18n] Failed to load locale ${lang}:`, err);
      return {};
    }
  }

  async function setLanguage(lang) {
    if (!SUPPORTED_LANGS.includes(lang)) lang = 'zh-TW';
    currentLang = lang;
    try {
      localStorage.setItem(STORAGE_KEY, lang);
    } catch (e) {}

    document.documentElement.lang = lang === 'en-US' ? 'en' : 'zh-Hant';

    const dict = await fetchLocaleJson(lang);

    document.querySelectorAll('[data-i18n]').forEach((el) => {
      const key = el.getAttribute('data-i18n');
      if (dict && dict[key] !== undefined) {
        if (el.tagName === 'META') {
          el.setAttribute('content', dict[key]);
        } else {
          el.textContent = dict[key];
        }
      }
    });

    // Update capsule button active states
    const btnZh = document.getElementById('langBtnZh');
    const btnEn = document.getElementById('langBtnEn');
    if (btnZh && btnEn) {
      if (lang === 'zh-TW') {
        btnZh.setAttribute('data-active', 'true');
        btnEn.setAttribute('data-active', 'false');
      } else {
        btnZh.setAttribute('data-active', 'false');
        btnEn.setAttribute('data-active', 'true');
      }
    }

    // Dispatch custom event so dynamic components (Pricing Plans & Dynamic Gallery) re-render immediately
    window.dispatchEvent(
      new CustomEvent('tcstorefront:langchange', {
        detail: { lang: currentLang, dict }
      })
    );
  }

  function getLanguage() {
    return currentLang;
  }

  window.TCStorefrontI18n = {
    setLanguage,
    getLanguage,
    fetchLocaleJson
  };

  document.addEventListener('DOMContentLoaded', () => {
    const btnZh = document.getElementById('langBtnZh');
    const btnEn = document.getElementById('langBtnEn');
    const toggleCapsule = document.getElementById('langToggleCapsule');

    if (btnZh) {
      btnZh.addEventListener('click', (e) => {
        e.stopPropagation();
        setLanguage('zh-TW');
      });
    }
    if (btnEn) {
      btnEn.addEventListener('click', (e) => {
        e.stopPropagation();
        setLanguage('en-US');
      });
    }
    if (toggleCapsule && !btnZh && !btnEn) {
      toggleCapsule.addEventListener('click', () => {
        setLanguage(currentLang === 'zh-TW' ? 'en-US' : 'zh-TW');
      });
    }

    setLanguage(currentLang);
  });
})();
