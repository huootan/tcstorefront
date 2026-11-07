/**
 * tcstorefront Frontend Synthesis & Dynamic Gallery Controller
 * Agent: frontend_synthesis_engineer
 *
 * Responsibilities:
 * 1. Minimalist sticky navbar scroll transitions (tucheng-store-rental aesthetic)
 * 2. Bilingual interactive 4-option rental plan comparison calculator
 * 3. Dynamic Data-Driven Gallery: Prioritizes Firebase Firestore/Storage (`gallery_photos` collection)
 *    with graceful offline/unconfigured fallback to `assets_manifest.json`
 * 4. Strict XSS sanitization (HTML escaping & DOM API creation) for all dynamic captions
 * 5. Stealth Admin Trigger: 5-click gesture on footer copyright, `Ctrl+Shift+A`, or `#stealth-admin` hash
 *    to lazy-load `./js/admin_portal.js`
 */
(function () {
  let currentPlan = 'longterm';
  let currentFilter = 'all';
  let manifestData = null;
  let activeGalleryPhotos = [];
  let adminPortalLoaded = false;
  let adminPortalLoading = false;

  // Load Firebase runtime config strictly from localStorage (Zero hardcoded API keys in source code)
  if (!window.__FIREBASE_CONFIG__) {
    try {
      const savedCfg = localStorage.getItem('tcstorefront_firebase_runtime_config');
      if (savedCfg) {
        window.__FIREBASE_CONFIG__ = JSON.parse(savedCfg);
      }
    } catch (e) {}
  }

  // Safe HTML Escaping to prevent Stored XSS in dynamic photo captions
  function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Validate image URLs strictly (reject quotes/parens/newlines to prevent CSS injection and enforce relative ./assets/ or https://)
  function sanitizeImageUrl(url) {
    if (typeof url !== 'string') return '';
    const trimmed = url.trim();
    if (/['"()\\<>`\r\n\t]/.test(trimmed)) return '';
    if (trimmed.startsWith('./assets/') || trimmed.startsWith('assets/')) {
      return trimmed.includes('..') ? '' : trimmed;
    }
    if (trimmed.startsWith('https://')) {
      try {
        const parsed = new URL(trimmed);
        return parsed.protocol === 'https:' ? parsed.href : '';
      } catch (e) {
        return '';
      }
    }
    return '';
  }

  // Bilingual 4-Option Rental Plans Data (100% accurate to Qingyun Rd. No. 341 specs)
  const PLANS_DATA = {
    'zh-TW': {
      longterm: {
        badge: '主推方案 · 企業展店首選',
        title: 'Option 01｜長期旗艦進駐（連鎖品牌／診所／大型餐飲零售）',
        price: 'NT$ 120,000 / 月（含稅＋含每月約 $8,000 管理費）',
        summary:
          '一般店面月租 12 萬若外加 10% 租賃稅（$12,000）與管理費（$8,000），企業每月實際支出高達 $140,000！本物件由屋主直接吸收稅金與管理費，簽約滿 5 年再享前 3 個月免租裝潢期。',
        metrics: [
          { label: '扣除管理費後實質月租', value: '約 NT$ 112,000 / 月', sub: '管理費每月約 $8,000 由屋主負擔' },
          { label: '發票與報稅條件', value: '含稅價（可正式營登）', sub: '幫企業省下 10% 租賃稅額外支出' },
          { label: '5 年長約免租期優惠', value: '前 3 個月免收租金', sub: '直接幫企業省下 NT$ 360,000 裝潢期房租' }
        ],
        bullets: [
          '押金僅需 2 個月（NT$ 240,000），大幅減輕企業初期資金壓力。',
          'B-3 一般零售業使用執照，具備三相電、天然氣、排煙排水系統與專屬卸貨區。',
          '距離機車停車場 20 公尺、青山汽車停車場 30 公尺，正對青山廣場公園，自帶穩定家庭與休閒客源。'
        ]
      },
      shortterm: {
        badge: '1～3 個月彈性租期 · 免長約綁定',
        title: 'Option 02｜短期快閃店／換季特賣會（1–3 個月）',
        price: 'NT$ 180,000 / 月',
        summary:
          '適合服飾鞋包換季特賣會、年貨大街、家電展售、建案臨時接待中心或新品牌市場水溫測試，享受 9 公尺超大面寬廣告效益與正對公園的週末人潮。',
        metrics: [
          { label: '適用租期長度', value: '1 至 3 個月', sub: '免受多年長約限制，檔期靈活' },
          { label: '短期月租金', value: 'NT$ 180,000 / 月', sub: '室內 47.7 坪（157.7 m²）挑高方正空間全區使用' },
          { label: '集客與物流優勢', value: '專屬卸貨區＋30m 停車場', sub: '進撤場貨車上下貨與顧客採買停車超便利' }
        ],
        bullets: [
          '9 公尺大面寬落地窗正對青雲路與青山廣場，招牌能見度極高，省下大量外部廣告費。',
          '室內無複雜隔間、地坪平整、挑高 4.6 公尺，花車與展示架進場即可立刻營業。',
          '門口即公車站牌，周邊清水生活圈與重劃區新大樓住戶密集，採買動能強。'
        ]
      },
      daily: {
        badge: '單日活動／快閃市集／品牌發表',
        title: 'Option 03｜單日快閃租借／活動展演空間',
        price: 'NT$ 10,000 / 日',
        summary:
          '需要大坪數、挑高採光好且客人超好停車的一樓場地？提供單日快閃租借，適合一日限定特賣、團購取貨快閃、品牌體驗會、社區推廣活動或商業攝影。',
        metrics: [
          { label: '單日租金定價', value: 'NT$ 10,000 / 日', sub: '可使用室內 47.7 坪（157.7 m²）挑高大空間' },
          { label: '空間尺度', value: '面寬 9m × 深度 15m', sub: '挑高 4.6 公尺開闊無壓迫感，採光極佳' },
          { label: '顧客停車距離', value: '汽機車停車場 20–30m', sub: '參加活動免繞圈找車位' }
        ],
        bullets: [
          '一樓臨路免爬樓梯、附設專屬卸貨區，活動道具與展品搬運最省力。',
          '正對青山廣場綠意，落地窗自然採光充足，拍照打卡視覺效果極佳。',
          '如需連續多日租借或週末檔期預約，歡迎直接加 LINE 洽詢屋主鄭先生 / 鄭太太。'
        ]
      },
      split: {
        badge: '降低進駐門檻 · 複合式經營',
        title: 'Option 04｜微型創業／空間分割合租方案',
        price: '依分割坪數與配置專案洽談',
        summary:
          '覺得 47.7 坪（157.7 m²）單一品牌承租太大？本空間面寬達 9 公尺、深度約 15 公尺，具備極佳的雙店面或複合式分割潛力，歡迎雙品牌聯合承租或洽談分割方案！',
        metrics: [
          { label: '全區室內實坪', value: '47.7 坪（權狀 80 坪）', sub: '若對半分割，單間實坪約 23–24 坪（約 78 m²）' },
          { label: '適合複合業態組合', value: '咖啡烘焙 × 選物 / 診所 × 藥局', sub: '美業工作室、物理治療、輕食皆宜' },
          { label: '硬體共用優勢', value: '三相電＋排煙排水齊備', sub: '大幅降低單一品牌初期開辦成本' }
        ],
        bullets: [
          '9 公尺大面寬即使對半分割，單間仍擁有約 4.5 公尺漂亮面寬與獨立落地窗展示面。',
          '歡迎創業者找伴合租，或直接聯繫屋主鄭先生 / 鄭太太討論空間分割構想。'
        ]
      }
    },
    'en-US': {
      longterm: {
        badge: 'FLAGSHIP CHOICE · BEST VALUE FOR CHAINS',
        title: 'Option 01｜Long-Term Flagship Lease (Chain Retail / Clinic / F&B)',
        price: 'NT$ 120,000 / mo (Tax & ~NT$8,000 Mgmt Fee Included)',
        summary:
          'In standard commercial leases, a NT$120K base rent plus 10% rental tax (NT$12K) and management fee (NT$8K) actually costs the tenant NT$140,000/month! Here, the owner covers both tax and management fees—plus a 5-year lease includes a 3-month rent-free fit-out period.',
        metrics: [
          { label: 'Effective Net Rent (Ex-Mgmt)', value: '~NT$ 112,000 / mo', sub: 'Owner covers the ~NT$8,000/mo management fee' },
          { label: 'Tax & Business Registration', value: 'Tax-Inclusive', sub: 'Saves corporate tenants 10% rental tax' },
          { label: '5-Year Lease Incentive', value: '3 Months Rent-Free Fit-Out', sub: 'Saves NT$ 360,000 during your renovation period' }
        ],
        bullets: [
          'Only 2 months security deposit (NT$ 240,000), preserving your working capital.',
          'B-3 General Retail Occupancy Permit with 3-phase power, natural gas, exhaust/drainage, and loading zone.',
          'Just 20m to scooter parking and 30m to Qingshan Car Park, directly facing Qingshan Plaza Park.'
        ]
      },
      shortterm: {
        badge: '1–3 MONTHS FLEXIBLE TERM · NO LONG LOCK-IN',
        title: 'Option 02｜Short-Term Pop-Up Lease Options (1–3 Months)',
        price: 'NT$ 180,000 / month',
        summary:
          'Ideal for seasonal apparel/footwear clearance sales, holiday markets, appliance expos, real estate reception centers, or brand market testing with 9m frontage visibility.',
        metrics: [
          { label: 'Lease Duration', value: '1 to 3 Months', sub: 'Flexible scheduling without multi-year commitment' },
          { label: 'Short-Term Monthly Rate', value: 'NT$ 180,000 / mo', sub: 'Full access to 47.7 Ping (157.7 sq.m.) interior' },
          { label: 'Logistics & Parking', value: 'Loading Zone + 30m Parking', sub: 'Effortless truck unloading & customer parking' }
        ],
        bullets: [
          '9m floor-to-ceiling glass frontage facing Qingyun Rd. & Qingshan Park delivers massive billboard value.',
          'Open rectangular floor plate with 4.6m ceiling—ready for immediate merchandising.',
          'Surrounded by high-density residential complexes and mature Qingshui neighborhood shoppers.'
        ]
      },
      daily: {
        badge: 'SINGLE-DAY EVENTS / FLASH SALES / PRODUCTIONS',
        title: 'Option 03｜Single-Day Pop-Up & Event Space Rental',
        price: 'NT$ 10,000 / day',
        summary:
          'Need a bright, high-ceiling ground-floor venue with effortless parking? Available for single-day flash sales, group-buying pickup events, product launches, community workshops, or commercial shoots.',
        metrics: [
          { label: 'Daily Rental Rate', value: 'NT$ 10,000 / day', sub: 'Full 47.7 Ping (157.7 sq.m.) ground-floor space' },
          { label: 'Spatial Dimensions', value: '9m W × 15m D × 4.6m H', sub: 'Spacious, airy, and filled with natural light' },
          { label: 'Visitor Parking', value: '20–30m to Parking Lots', sub: 'Hassle-free arrival for guests and VIPs' }
        ],
        bullets: [
          'Ground-floor street access with dedicated loading zone makes moving equipment and props effortless.',
          'Lush green views of Qingshan Park through expansive windows create a stunning backdrop.',
          'Contact Owner Mr. / Mrs. Cheng on LINE to check weekend or multi-day availability.'
        ]
      },
      split: {
        badge: 'LOWER ENTRY THRESHOLD · CO-BRANDED CONCEPT',
        title: 'Option 04｜Micro-Business / Subdivided Co-Lease Plan',
        price: 'Custom Quoted by Subdivided Area',
        summary:
          'Is 47.7 Ping (157.7 sq.m.) too large for your solo concept? With a 9m frontage and 15m depth, the space can be subdivided into dual storefronts or shared by complementary brands!',
        metrics: [
          { label: 'Total Net Interior', value: '47.7 Ping (157.7 sq.m.)', sub: '~23–24 Ping (~78 sq.m.) per unit if split 50/50' },
          { label: 'Ideal Co-Lease Pairs', value: 'Cafe × Select Shop / Clinic × Pharmacy', sub: 'Also great for beauty studios & therapy clinics' },
          { label: 'Shared Infrastructure', value: '3-Phase Power & Exhaust Ready', sub: 'Significantly reduces initial setup costs' }
        ],
        bullets: [
          'Even split in half, each unit enjoys a generous ~4.5m storefront width with street-facing glass.',
          'Bring a partner brand or message Mr. / Mrs. Cheng to discuss custom subdivision possibilities.'
        ]
      }
    }
  };

  function getLang() {
    return window.TCStorefrontI18n ? window.TCStorefrontI18n.getLanguage() : 'zh-TW';
  }

  // 1. Sticky Navbar Scroll Behavior (tucheng-store-rental style)
  function initHeaderScroll() {
    const header = document.getElementById('mainHeader');
    const brandLink = document.getElementById('brandLink');
    const callBtn = document.getElementById('headerCallBtn');
    const capsule = document.getElementById('langToggleCapsule');
    const navLinks = document.querySelectorAll('.nav-link');

    function updateHeader() {
      const scrolled = window.scrollY > 60;
      if (!header) return;
      if (scrolled) {
        header.className =
          'header-scrolled fixed top-0 left-0 right-0 z-50 transition-all duration-500 border-b bg-white/95 backdrop-blur-md border-neutral-200 py-3.5 shadow-sm';
        if (brandLink) brandLink.className = 'text-sm sm:text-lg md:text-xl tracking-[0.1em] md:tracking-[0.18em] text-neutral-900 transition-colors shrink-0';
        if (callBtn) callBtn.className = 'px-3.5 sm:px-5 py-2 text-xs tracking-widest uppercase border bg-neutral-900 text-white border-neutral-900 hover:bg-neutral-800 transition-colors shrink-0';
        if (capsule) capsule.className = 'lang-capsule inline-flex items-center border border-neutral-300 rounded-full p-0.5 text-xs tracking-wider transition-colors';
        navLinks.forEach((l) => {
          l.classList.remove('text-neutral-200', 'hover:text-white');
          l.classList.add('text-neutral-500', 'hover:text-neutral-900');
        });
      } else {
        header.className =
          'header-transparent fixed top-0 left-0 right-0 z-50 transition-all duration-500 border-b border-transparent bg-transparent py-5';
        if (brandLink) brandLink.className = 'text-sm sm:text-lg md:text-xl tracking-[0.1em] md:tracking-[0.18em] text-white transition-colors shrink-0';
        if (callBtn) callBtn.className = 'px-3.5 sm:px-5 py-2 text-xs tracking-widest uppercase border bg-white text-neutral-900 border-white hover:bg-neutral-100 transition-colors shrink-0';
        if (capsule) capsule.className = 'lang-capsule inline-flex items-center border border-white/40 rounded-full p-0.5 text-xs tracking-wider transition-colors';
        navLinks.forEach((l) => {
          l.classList.add('text-neutral-200', 'hover:text-white');
          l.classList.remove('text-neutral-500', 'hover:text-neutral-900');
        });
      }
    }

    window.addEventListener('scroll', updateHeader, { passive: true });
    updateHeader();
  }

  // 2. Render Interactive Rental Plans
  function renderPlan(planKey) {
    if (planKey) currentPlan = planKey;
    const lang = getLang();
    const langPlans = PLANS_DATA[lang] || PLANS_DATA['zh-TW'];
    const data = langPlans[currentPlan] || langPlans.longterm;
    const panel = document.getElementById('planContentPanel');
    if (!panel || !data) return;

    const metricsHtml = data.metrics
      .map(
        (m) => `
      <div class="border border-neutral-800 bg-neutral-950/90 p-5">
        <div class="text-xs tracking-wider uppercase text-neutral-400 mb-1.5">${escapeHtml(m.label)}</div>
        <div class="text-lg sm:text-xl font-medium text-amber-400 tracking-wide">${escapeHtml(m.value)}</div>
        <div class="text-xs text-neutral-400 font-light mt-1.5">${escapeHtml(m.sub)}</div>
      </div>
    `
      )
      .join('');

    const bulletsHtml = data.bullets
      .map(
        (b) => `
      <li class="flex items-start gap-3 text-sm text-neutral-300 font-light">
        <span class="text-amber-400 mt-0.5">✓</span>
        <span>${escapeHtml(b)}</span>
      </li>
    `
      )
      .join('');

    panel.innerHTML = `
      <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b border-neutral-800">
        <div>
          <span class="inline-block text-[11px] tracking-[0.2em] uppercase text-amber-400 mb-2">${escapeHtml(data.badge)}</span>
          <h3 class="text-xl sm:text-2xl font-light text-white tracking-wide">${escapeHtml(data.title)}</h3>
        </div>
        <div class="border border-amber-400/60 bg-amber-400/10 text-amber-300 px-5 py-3 text-sm sm:text-base font-medium tracking-wide shrink-0">
          ${escapeHtml(data.price)}
        </div>
      </div>
      <p class="text-neutral-300 text-sm sm:text-base font-light leading-relaxed my-6">${escapeHtml(data.summary)}</p>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">${metricsHtml}</div>
      <ul class="space-y-3 bg-neutral-950/60 p-6 border border-neutral-800/90">${bulletsHtml}</ul>
    `;

    document.querySelectorAll('.plan-tab').forEach((btn) => {
      if (btn.getAttribute('data-plan') === currentPlan) {
        btn.className = 'plan-tab border border-white bg-white text-neutral-900 p-5 text-left transition-all';
      } else {
        btn.className =
          'plan-tab border border-neutral-800 bg-neutral-900/60 text-neutral-300 hover:border-neutral-600 p-5 text-left transition-all';
      }
    });
  }

  // 3. Dynamic Data-Driven Photo Gallery & Manifest Loader
  async function loadInitialManifest() {
    try {
      const res = await fetch('./assets_manifest.json', { cache: 'no-cache' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      manifestData = await res.json();
    } catch (e) {
      // Fallback manifest if opened directly via file://
      manifestData = {
        hero_background: './assets/initial_photos/p3.jpg',
        floor_plan_image: './assets/initial_photos/p1.jpg',
        transit_maps: [
          {
            id: 'transit_lg10',
            src: './assets/initial_photos/中正國中站LG10.png',
            title_zh: '未來萬大線 LG10 中正國中站',
            title_en: 'Future Wanda MRT Line LG10 Station'
          },
          {
            id: 'transit_highway3',
            src: './assets/initial_photos/國3金城交流道.png',
            title_zh: '國道 3 號金城交流道',
            title_en: 'National Freeway No. 3 Jincheng Interchange'
          }
        ],
        initial_gallery_photos: [
          {
            id: 'init_p5',
            order: 1,
            src: './assets/initial_photos/p5.jpg',
            category: 'interior',
            tag_zh: '室內看公園視角',
            tag_en: 'Park View from Inside',
            title_zh: '店內往外看落地窗與青山廣場綠意',
            title_en: 'Interior View Looking Out to Qingshan Park',
            desc_zh: '站在挑高 4.6 米室內朝大門拍攝，9 米大面寬採光極佳，開門即見對面青山廣場綠樹。',
            desc_en: 'Shot from inside the 4.6m high-ceiling space toward the 9m glass entrance facing lush Qingshan Park.'
          },
          {
            id: 'init_p4',
            order: 2,
            src: './assets/initial_photos/p4.jpg',
            category: 'interior',
            tag_zh: '挑高 4.6m 室內',
            tag_en: '4.6m High Interior',
            title_zh: '47.7 坪挑高 4.6 米寬敞方正室內實景',
            title_en: '47.7-Ping (157.7 sq.m.) Interior with 4.6m High Ceiling',
            desc_zh: '室內縱深約 15 米、格局方正無壓迫感，具備三相電、天然氣與排煙排水管線。',
            desc_en: 'Approx. 15m deep rectangular layout equipped with 3-phase power, natural gas, exhaust, and drainage.'
          },
          {
            id: 'init_p1',
            order: 3,
            src: './assets/initial_photos/p1.jpg',
            category: 'interior',
            tag_zh: '平面尺寸圖',
            tag_en: 'Floor Plan (cm)',
            title_zh: '1F 室內平面尺寸配置圖 (單位：cm)',
            title_en: '1F Interior Dimension Floor Plan (Unit: cm)',
            desc_zh: '清楚標示青雲路 15M 計畫道路、面寬段 1025cm、室內跨距 960cm 與梯廳機電位置。',
            desc_en: 'Detailed measurements showing 15M Qingyun Rd., 1025cm frontage span, 960cm interior width & core areas.'
          },
          {
            id: 'init_p2',
            order: 4,
            src: './assets/initial_photos/p2.jpg',
            category: 'exterior',
            tag_zh: '對面廣場與停車場',
            tag_en: 'Park & Parking View',
            title_zh: '正對青山廣場公園與對面停車場視角',
            title_en: 'Directly Across from Qingshan Park & Parking Lots',
            desc_zh: '店面正對面即為綠意廣場與停車場方向（機車停車場 20m、汽車停車場 30m），顧客停車免煩惱。',
            desc_en: 'Facing green plaza and public parking (scooter lot 20m, car park 30m away) for effortless customer visits.'
          },
          {
            id: 'init_p3',
            order: 5,
            src: './assets/initial_photos/p3.jpg',
            category: 'exterior',
            tag_zh: '建築外觀與公車站',
            tag_en: 'Facade & Bus Stop',
            title_zh: '新成屋大樓氣派外觀與門口公車站牌',
            title_en: 'Modern Building Facade & Bus Stop at Doorstep',
            desc_zh: '位於青雲路 341 號 1F（竑實想樂社區），門口即有公車候車亭直達捷運海山站。',
            desc_en: '1F, No. 341, Qingyun Rd. with a bus shelter right in front connecting directly to Haishan MRT Station.'
          },
          {
            id: 'init_p6',
            order: 6,
            src: './assets/initial_photos/p6.jpg',
            category: 'exterior',
            tag_zh: '9米大面寬門面',
            tag_en: '9m Storefront',
            title_zh: '大面寬門市招牌視覺與商業氛圍',
            title_en: 'High-Visibility Storefront Signage & Commercial Vibe',
            desc_zh: '9 米大面寬加上挑高門面，品牌招牌醒目大器，路過車流與公園人潮一眼聚焦。',
            desc_en: 'Commanding 9m frontage ensures maximum brand exposure to passing traffic and park visitors.'
          },
          {
            id: 'init_p7',
            order: 7,
            src: './assets/initial_photos/p7.jpg',
            category: 'exterior',
            tag_zh: '門前人行道實景',
            tag_en: 'Pedestrian Walkway',
            title_zh: '門前綠蔭人行步道與公車候車動線',
            title_en: 'Tree-Lined Pedestrian Walkway in Front of Store',
            desc_zh: '緊鄰清水成熟商圈與土城暫緩重劃區交界，退縮綠蔭人行道舒適寬敞。',
            desc_en: 'Wide, welcoming setback sidewalk at the junction of Qingshui commercial district and Tucheng redevelopment zone.'
          }
        ]
      };
    }

    // Bind Hero background, Floor Plan, Park View, and Transit Maps dynamically
    const heroBg = document.getElementById('heroBgLayer');
    if (heroBg && manifestData.hero_background) {
      heroBg.style.backgroundImage = `url('${sanitizeImageUrl(manifestData.hero_background)}')`;
    }

    const fpImg = document.getElementById('floorplanImg');
    if (fpImg && manifestData.floor_plan_image) {
      fpImg.src = sanitizeImageUrl(manifestData.floor_plan_image);
    }

    const parkImg = document.getElementById('parkViewImg');
    if (parkImg) {
      parkImg.src = './assets/initial_photos/p2.jpg';
    }

    renderTransitMaps();

    // Initialize gallery with manifest photos first, then check cloud / local overrides
    activeGalleryPhotos = Array.isArray(manifestData.initial_gallery_photos)
      ? [...manifestData.initial_gallery_photos]
      : [];

    await syncCloudGalleryIfConfigured();
    renderGallery(currentFilter);
  }

  // Cloud Firestore Dynamic Sync Hook (with Graceful Fallback)
  async function syncCloudGalleryIfConfigured() {
    // Check if admin portal or firebase config has synced custom gallery state
    try {
      const cachedCustom = localStorage.getItem('tcstorefront_gallery_cache');
      if (cachedCustom) {
        const parsed = JSON.parse(cachedCustom);
        if (Array.isArray(parsed) && parsed.length > 0) {
          const validCached = parsed.filter(
            (p) => p && typeof p === 'object' && sanitizeImageUrl(p.src) !== ''
          );
          if (validCached.length > 0) {
            activeGalleryPhotos = validCached;
          }
        }
      }
    } catch (e) {}

    // If Firebase Firestore is configured on window.__FIREBASE_CONFIG__, fetch live collection `gallery_photos`
    const fbConfig = window.__FIREBASE_CONFIG__;
    if (fbConfig && fbConfig.projectId && fbConfig.projectId !== 'YOUR_FIREBASE_PROJECT_ID') {
      try {
        const firestoreUrl = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(
          fbConfig.projectId
        )}/databases/(default)/documents/gallery_photos?pageSize=50`;
        const response = await fetch(firestoreUrl);
        if (response.ok) {
          const data = await response.json();
          if (data.documents && data.documents.length > 0) {
            const cloudPhotos = data.documents
              .map((doc) => {
                const f = doc.fields || {};
                const docId = doc.name ? doc.name.split('/').pop() : '';
                return {
                  id: docId,
                  order: f.order && f.order.integerValue ? parseInt(f.order.integerValue, 10) : 99,
                  src: f.src && f.src.stringValue ? f.src.stringValue : '',
                  storagePath: f.storagePath && f.storagePath.stringValue ? f.storagePath.stringValue : '',
                  category: f.category && f.category.stringValue ? f.category.stringValue : 'interior',
                  tag_zh: f.tag_zh && f.tag_zh.stringValue ? f.tag_zh.stringValue : '精選實景',
                  tag_en: f.tag_en && f.tag_en.stringValue ? f.tag_en.stringValue : 'Featured',
                  title_zh: f.title_zh && f.title_zh.stringValue ? f.title_zh.stringValue : '',
                  title_en: f.title_en && f.title_en.stringValue ? f.title_en.stringValue : '',
                  desc_zh: f.desc_zh && f.desc_zh.stringValue ? f.desc_zh.stringValue : '',
                  desc_en: f.desc_en && f.desc_en.stringValue ? f.desc_en.stringValue : ''
                };
              })
              .filter((item) => sanitizeImageUrl(item.src) !== '')
              .sort((a, b) => a.order - b.order);

            if (cloudPhotos.length > 0) {
              activeGalleryPhotos = cloudPhotos;
              try {
                localStorage.setItem('tcstorefront_gallery_cache', JSON.stringify(cloudPhotos));
              } catch (e) {}
            }
          }
        }
      } catch (err) {
        // Silently degrade to fallback manifest photos
      }
    }
  }

  function renderTransitMaps() {
    const container = document.getElementById('transitMapsContainer');
    if (!container || !manifestData || !Array.isArray(manifestData.transit_maps)) return;
    const isEn = getLang() === 'en-US';
    container.innerHTML = '';

    manifestData.transit_maps.forEach((item) => {
      const safeSrc = sanitizeImageUrl(item.src);
      if (!safeSrc) return;
      const title = isEn ? item.title_en : item.title_zh;
      const fig = document.createElement('figure');
      fig.className = 'bg-neutral-50 border border-neutral-200 p-4 m-0 cursor-pointer group';

      const cap = document.createElement('figcaption');
      cap.className = 'text-xs tracking-widest uppercase text-neutral-500 mb-3 flex items-center justify-between';
      cap.textContent = title;

      const img = document.createElement('img');
      img.src = safeSrc;
      img.alt = title;
      img.className = 'w-full h-auto object-contain group-hover:scale-[1.01] transition-transform duration-300';

      fig.appendChild(cap);
      fig.appendChild(img);
      fig.addEventListener('click', () => openLightbox(safeSrc, title));
      container.appendChild(fig);
    });
  }

  // Render Dynamic Photo Gallery using DOM API (textContent) to strictly prevent Stored XSS
  function renderGallery(filter) {
    if (filter) currentFilter = filter;
    const grid = document.getElementById('galleryGrid');
    if (!grid) return;

    const isEn = getLang() === 'en-US';
    const items =
      currentFilter === 'all'
        ? activeGalleryPhotos
        : activeGalleryPhotos.filter((p) => p.category === currentFilter);

    grid.innerHTML = '';

    items.forEach((item) => {
      const safeSrc = sanitizeImageUrl(item.src);
      if (!safeSrc) return;

      const title = (isEn ? item.title_en || item.title_zh : item.title_zh || item.title_en) || '';
      const desc = (isEn ? item.desc_en || item.desc_zh : item.desc_zh || item.desc_en) || '';
      const tag = (isEn ? item.tag_en || item.tag_zh : item.tag_zh || item.tag_en) || '';

      const card = document.createElement('article');
      card.className = 'group border border-neutral-200 bg-white overflow-hidden cursor-pointer flex flex-col';

      const imgWrap = document.createElement('div');
      imgWrap.className = 'relative h-[280px] lg:h-[360px] overflow-hidden bg-neutral-100';

      const img = document.createElement('img');
      img.src = safeSrc;
      img.alt = title;
      img.loading = 'lazy';
      img.className = 'absolute inset-0 w-full h-full object-cover editorial-img group-hover:scale-105';

      const badge = document.createElement('span');
      badge.className =
        'absolute top-4 left-4 bg-black/80 text-white text-[11px] tracking-widest uppercase px-3 py-1 backdrop-blur-sm';
      badge.textContent = tag;

      imgWrap.appendChild(img);
      if (tag) imgWrap.appendChild(badge);

      const body = document.createElement('div');
      body.className = 'p-5 flex-1 flex flex-col justify-between bg-white';

      const h3 = document.createElement('h3');
      h3.className = 'text-base font-medium text-neutral-900 mb-1.5 tracking-wide';
      h3.textContent = title;

      const p = document.createElement('p');
      p.className = 'text-xs text-neutral-500 font-light leading-relaxed';
      p.textContent = desc;

      body.appendChild(h3);
      body.appendChild(p);

      card.appendChild(imgWrap);
      card.appendChild(body);

      card.addEventListener('click', () => {
        openLightbox(safeSrc, title);
      });

      grid.appendChild(card);
    });

    // Update filter buttons
    document.querySelectorAll('.gallery-filter').forEach((btn) => {
      if (btn.getAttribute('data-filter') === currentFilter) {
        btn.className =
          'gallery-filter border border-neutral-900 bg-neutral-900 text-white text-xs tracking-widest uppercase px-4 py-2.5 transition';
      } else {
        btn.className =
          'gallery-filter border border-neutral-300 bg-white text-neutral-700 hover:border-neutral-900 text-xs tracking-widest uppercase px-4 py-2.5 transition';
      }
    });
  }

  function openLightbox(src, caption) {
    const modal = document.getElementById('lightboxModal');
    const img = document.getElementById('lightboxImg');
    const cap = document.getElementById('lightboxCaption');
    if (!modal || !img || !cap) return;
    img.src = sanitizeImageUrl(src);
    cap.textContent = caption || '';
    modal.classList.remove('hidden');
  }

  function closeLightbox() {
    const modal = document.getElementById('lightboxModal');
    if (modal) modal.classList.add('hidden');
  }

  function copyPropertySpecs() {
    const isEn = getLang() === 'en-US';
    const textZh = [
      '【新北土城重劃區｜青雲路341號1F・9米大面寬×4.6米挑高金店面出租】',
      '📍 地址：新北市土城區青雲路 341 號 1F（正對青山廣場公園）',
      '📐 坪數尺度：總坪數 80 坪（264.5 m²）／ 室內實坪 47.7 坪（157.7 m²），面寬 9 公尺 × 深度約 15 公尺 × 挑高 4.6 公尺',
      '🏛️ 使用執照：B-3 一般零售業使用執照（可正式辦理營業登記）',
      '💰 長租條件：月租 NT$ 120,000 元（含稅及每月約 8,000 元管理費）、押金 2 個月、5 年長約享前 3 個月免租裝潢期',
      '⚡ 短租快閃方案：1~3 個月期月租 NT$ 180,000 元、單日租 NT$ 10,000 元/日',
      '🔧 硬體設備：三相電、天然氣、排煙排水系統、專屬卸貨區',
      '🚗 停車與交通：機車停車場 20m、青山汽車停車場 30m；門口公車直達捷運海山站，步行可達未來萬大線 LG10 站',
      '📞 聯絡人：鄭先生 / 鄭太太 0955-599-119（屋主自租免仲介費，歡迎房仲合作配案）',
      '💬 LINE 連結：https://line.me/ti/p/aM-a4jS34u'
    ].join('\n');

    const textEn = [
      '【Prime 1F Flagship Storefront for Lease | No. 341 Qingyun Rd., Tucheng Dist., New Taipei City】',
      '📍 Address: 1F, No. 341, Qingyun Rd., Tucheng Dist., New Taipei City (Directly facing Qingshan Park)',
      '📐 Dimensions: Gross 80 Ping (264.5 sq.m.) / Net Interior 47.7 Ping (157.7 sq.m.) | 9m Width × 15m Depth × 4.6m Ceiling',
      '🏛️ Permit: B-3 General Retail Occupancy Permit (Official business registration ready)',
      '💰 Long-Term Lease: NT$ 120,000/mo (Tax & ~NT$8,000/mo management fee included), 2-month deposit; 5-year lease includes a 3-month rent-free fit-out period',
      '⚡ Short-Term Pop-Up Lease Options: NT$180,000/mo for 1–3 months, or NT$10,000/day',
      '🔧 Infrastructure: 3-phase power, natural gas, exhaust & drainage systems, dedicated loading zone',
      '🚗 Parking & Transit: 20m to scooter parking, 30m to Qingshan Car Park; bus at doorstep to Haishan MRT Station',
      '📞 Contact: Owner Mr. / Mrs. Cheng 0955-599-119 (Direct tenants & commercial brokers welcome)',
      '💬 LINE Contact: https://line.me/ti/p/aM-a4jS34u'
    ].join('\n');

    const text = isEn ? textEn : textZh;

    const showToast = () => {
      const toast = document.getElementById('toastNotice');
      if (!toast) return;
      toast.classList.remove('hidden');
      setTimeout(() => toast.classList.add('hidden'), 3200);
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(showToast);
    }
  }

  // 4. Stealth Admin Trigger (5-click on footer copyright, Ctrl+Shift+A, or #stealth-admin hash)
  function loadAndOpenAdminPortal() {
    if (adminPortalLoaded && window.TCStorefrontAdmin) {
      window.TCStorefrontAdmin.openModal();
      return;
    }
    if (adminPortalLoading) return;
    adminPortalLoading = true;

    const script = document.createElement('script');
    script.src = './js/admin_portal.js';
    script.async = true;
    script.onload = () => {
      adminPortalLoaded = true;
      adminPortalLoading = false;
      if (window.TCStorefrontAdmin) {
        window.TCStorefrontAdmin.openModal();
      }
    };
    script.onerror = () => {
      adminPortalLoading = false;
      console.error('[StealthAdmin] Failed to load admin_portal.js');
    };
    document.body.appendChild(script);
  }

  function initStealthAdminTrigger() {
    let clickCount = 0;
    let clickTimer = null;

    const copyrightEl = document.getElementById('stealthCopyrightTrigger');
    if (copyrightEl) {
      copyrightEl.addEventListener('click', () => {
        clickCount += 1;
        if (clickTimer) clearTimeout(clickTimer);
        if (clickCount >= 5) {
          clickCount = 0;
          loadAndOpenAdminPortal();
        } else {
          clickTimer = setTimeout(() => {
            clickCount = 0;
          }, 1800);
        }
      });
    }

    window.addEventListener('keydown', (e) => {
      if (e.ctrlKey && e.shiftKey && (e.key === 'A' || e.key === 'a')) {
        e.preventDefault();
        loadAndOpenAdminPortal();
      }
    });

    function checkHashTrigger() {
      if (window.location.hash === '#stealth-admin') {
        loadAndOpenAdminPortal();
      }
    }
    window.addEventListener('hashchange', checkHashTrigger);
    checkHashTrigger();
  }

  // Expose public gallery hook for Admin Portal live updates
  window.TCStorefrontGallery = {
    getPhotos: () => [...activeGalleryPhotos],
    getDefaultPhotos: () =>
      manifestData && Array.isArray(manifestData.initial_gallery_photos)
        ? [...manifestData.initial_gallery_photos]
        : [],
    updatePhotos: (newPhotos) => {
      if (Array.isArray(newPhotos)) {
        activeGalleryPhotos = [...newPhotos];
        renderGallery(currentFilter);
      }
    }
  };

  document.addEventListener('DOMContentLoaded', () => {
    initHeaderScroll();
    renderPlan('longterm');
    loadInitialManifest();
    initStealthAdminTrigger();

    document.querySelectorAll('.plan-tab').forEach((btn) => {
      btn.addEventListener('click', () => renderPlan(btn.getAttribute('data-plan')));
    });

    document.querySelectorAll('.gallery-filter').forEach((btn) => {
      btn.addEventListener('click', () => renderGallery(btn.getAttribute('data-filter')));
    });

    const openFpBtn = document.getElementById('openFloorplanBtn');
    const fpContainer = document.getElementById('floorplanContainer');
    const parkContainer = document.getElementById('parkViewContainer');

    const openFpLightbox = () => {
      const isEn = getLang() === 'en-US';
      openLightbox(
        './assets/initial_photos/p1.jpg',
        isEn ? '1F Interior Dimension Floor Plan (Unit: cm)' : '1F 室內平面尺寸配置圖（單位：cm）'
      );
    };
    if (openFpBtn) openFpBtn.addEventListener('click', openFpLightbox);
    if (fpContainer) fpContainer.addEventListener('click', openFpLightbox);

    if (parkContainer) {
      parkContainer.addEventListener('click', () => {
        const isEn = getLang() === 'en-US';
        openLightbox(
          './assets/initial_photos/p2.jpg',
          isEn
            ? 'Directly Across from Qingshan Park & Public Parking Lots'
            : '正對青山廣場公園與對面汽機車停車場視角'
        );
      });
    }

    const closeLbBtn = document.getElementById('closeLightboxBtn');
    const lbModal = document.getElementById('lightboxModal');
    if (closeLbBtn) closeLbBtn.addEventListener('click', closeLightbox);
    if (lbModal) {
      lbModal.addEventListener('click', (e) => {
        if (e.target === lbModal) closeLightbox();
      });
    }

    const copyHero = document.getElementById('copySpecHeroBtn');
    const copyFooter = document.getElementById('copySpecFooterBtn');
    if (copyHero) copyHero.addEventListener('click', copyPropertySpecs);
    if (copyFooter) copyFooter.addEventListener('click', copyPropertySpecs);

    // Render QR Code
    const qrBox = document.getElementById('lineQrContainer');
    if (qrBox && window.QRCode) {
      new window.QRCode(qrBox, {
        text: 'https://line.me/ti/p/aM-a4jS34u',
        width: 148,
        height: 148,
        colorDark: '#171717',
        colorLight: '#ffffff'
      });
    }

    // Re-render dynamic sections when language changes
    window.addEventListener('tcstorefront:langchange', () => {
      renderPlan(currentPlan);
      renderGallery(currentFilter);
      renderTransitMaps();
    });
  });
})();
