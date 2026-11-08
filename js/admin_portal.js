/**
 * High-Security Stealth Admin Portal (Lazy-Loaded Module)
 * Agent: secops_admin_architect
 *
 * Security Enforcements:
 * 1. Zero hardcoded passwords, passcodes, or private keys in frontend code.
 * 2. Integrates Firebase Authentication (Google OAuth + Email/Password) with mandatory
 *    Admin UID Whitelist verification (`email_verified == true` && `uid in ADMIN_UID_WHITELIST`).
 * 3. Pre-upload validation: strictly `image/jpeg`, `image/png`, `image/webp` only, max file size 5MB,
 *    strict filename sanitization against Path Traversal & XSS, plus client-side Canvas image compression.
 * 4. Secondary Confirmation Modal before deleting any photo, syncing Cloud Storage + Firestore `gallery_photos`.
 * 5. Full Gallery List Editing & Batch Cloud Sync (`syncEntireGalleryListToFirestore`) so edits, reorders,
 *    and deletions of both default and uploaded photos propagate immediately to all public visitors.
 * 6. Strict HTML Escaping / DOM API creation to prevent Stored XSS.
 */
(function () {
  const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
  const MAX_UPLOAD_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB
  const CONFIG_STORAGE_KEY = 'tcstorefront_firebase_runtime_config';

  // Purge any legacy API keys stored in persistent localStorage from earlier versions
  try {
    localStorage.removeItem(CONFIG_STORAGE_KEY);
  } catch (e) {}

  // In-memory / session-only runtime config (API Key is NEVER written to persistent localStorage or source code)
  let sessionRuntimeConfig = {
    apiKey: '',
    authDomain: 'orderseefoo.firebaseapp.com',
    projectId: 'orderseefoo',
    storageBucket: 'orderseefoo.firebasestorage.app',
    adminUidWhitelist: ['GxxxNnuuMTbRN16P5Qzvl8nlJzC3']
  };

  let firebaseApp = null;
  let firebaseAuth = null;
  let firebaseDb = null;
  let firebaseStorage = null;
  let currentUser = null;
  let pendingDeletePhoto = null;
  let compressedUploadBlob = null;
  let compressedPreviewDataUrl = null;
  let sanitizedUploadFileName = '';

  // Edit Photo Modal State
  let editingPhotoTarget = null;
  let editReplacementBlob = null;
  let editReplacementDataUrl = null;
  let editReplacementFileName = '';

  // Strict HTML Escape utility
  function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Strict Filename Sanitizer (prevents Path Traversal ../ and XSS characters)
  function sanitizeFileName(rawName) {
    if (typeof rawName !== 'string') return 'photo_' + Date.now() + '.jpg';
    const base = rawName.split(/[\\/]/).pop() || 'photo';
    const parts = base.split('.');
    let ext = parts.length > 1 ? parts.pop().toLowerCase() : 'jpg';
    if (!['jpg', 'jpeg', 'png', 'webp'].includes(ext)) {
      ext = 'jpg';
    }
    const cleanStem = parts
      .join('_')
      .replace(/[^a-zA-Z0-9_-]/g, '_')
      .replace(/_+/g, '_')
      .slice(0, 48);
    return `${Date.now()}_${cleanStem || 'storefront'}.${ext}`;
  }

  function getRuntimeConfig() {
    try {
      const saved = sessionStorage.getItem(CONFIG_STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed && typeof parsed === 'object') {
          sessionRuntimeConfig = {
            ...sessionRuntimeConfig,
            ...parsed
          };
        }
      }
    } catch (e) {}
    return sessionRuntimeConfig;
  }

  function saveRuntimeConfig(cfg) {
    sessionRuntimeConfig = {
      ...sessionRuntimeConfig,
      ...cfg
    };
    window.__FIREBASE_CONFIG__ = {
      projectId: sessionRuntimeConfig.projectId
    };
    try {
      // Store only in ephemeral sessionStorage (automatically wiped when browser tab closes)
      sessionStorage.setItem(CONFIG_STORAGE_KEY, JSON.stringify(sessionRuntimeConfig));
      localStorage.removeItem(CONFIG_STORAGE_KEY);
    } catch (e) {}
  }

  function isUserAuthorizedAdmin(user, cfg) {
    if (!user || !user.uid) return false;
    if (user.emailVerified !== true) return false;
    const whitelist = Array.isArray(cfg.adminUidWhitelist) ? cfg.adminUidWhitelist : [];
    return whitelist.includes(user.uid);
  }

  // Validate image URLs strictly (reject quotes/parens/newlines and enforce relative ./assets/ or https://)
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

  // Normalize a photo object to strictly comply with `isValidPhotoDocument()` in `firestore.rules`
  function normalizePhotoForFirestore(rawPhoto, fallbackIndex, uid) {
    const rawId = typeof rawPhoto.id === 'string' && rawPhoto.id.trim() ? rawPhoto.id.trim() : `photo_${Date.now()}_${fallbackIndex}`;
    const safeId = rawId.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 64);
    const parsedOrder = parseInt(rawPhoto.order, 10);
    const safeOrder = !isNaN(parsedOrder) && parsedOrder >= 0 && parsedOrder <= 9999 ? parsedOrder : fallbackIndex + 1;
    let safeSrc = sanitizeImageUrl(rawPhoto.src || '');
    if (safeSrc.startsWith('assets/')) {
      safeSrc = './' + safeSrc;
    }
    const safeCategory = rawPhoto.category === 'exterior' ? 'exterior' : 'interior';
    const doc = {
      id: safeId,
      order: safeOrder,
      src: safeSrc.slice(0, 1024),
      storagePath: typeof rawPhoto.storagePath === 'string' ? rawPhoto.storagePath.slice(0, 256) : '',
      category: safeCategory,
      tag_zh: typeof rawPhoto.tag_zh === 'string' ? rawPhoto.tag_zh.trim().slice(0, 40) : '',
      tag_en: typeof rawPhoto.tag_en === 'string' ? rawPhoto.tag_en.trim().slice(0, 40) : '',
      title_zh: typeof rawPhoto.title_zh === 'string' && rawPhoto.title_zh.trim()
        ? rawPhoto.title_zh.trim().slice(0, 120)
        : '土城青雲路341號店面實景',
      title_en: typeof rawPhoto.title_en === 'string' && rawPhoto.title_en.trim()
        ? rawPhoto.title_en.trim().slice(0, 120)
        : 'Tucheng No. 341 Qingyun Rd. Storefront',
      desc_zh: typeof rawPhoto.desc_zh === 'string' ? rawPhoto.desc_zh.trim().slice(0, 200) : '',
      desc_en: typeof rawPhoto.desc_en === 'string' ? rawPhoto.desc_en.trim().slice(0, 200) : '',
      updatedAt: new Date().toISOString()
    };
    if (uid) {
      doc.uploadedByUid = uid;
    }
    return doc;
  }

  /**
   * Synchronizes the entire current gallery photo list to Firestore `gallery_photos` collection
   * and deletes any cloud documents that were removed from `photoList`.
   */
  async function syncEntireGalleryListToFirestore(photoList) {
    const cfg = getRuntimeConfig();
    if (!cfg.apiKey || !cfg.projectId || !firebaseDb || !isUserAuthorizedAdmin(currentUser, cfg)) {
      return { synced: false, reason: 'not_connected' };
    }

    const normalizedList = photoList
      .map((item, idx) => normalizePhotoForFirestore(item, idx, currentUser.uid))
      .filter((item) => item.src.length > 0);

    const activeIds = new Set(normalizedList.map((item) => item.id));
    const colRef = firebaseDb.collection('gallery_photos');
    const existingSnap = await colRef.get();
    const batch = firebaseDb.batch();

    // Remove any Firestore docs no longer present in the active list
    existingSnap.forEach((docSnap) => {
      if (!activeIds.has(docSnap.id)) {
        batch.delete(docSnap.ref);
      }
    });

    // Upsert all current photos in the active list
    normalizedList.forEach((docData) => {
      const docRef = colRef.doc(docData.id);
      batch.set(docRef, docData);
    });

    await batch.commit();
    return { synced: true, count: normalizedList.length, normalizedList };
  }

  // Verify binary file header (Magic Bytes) for JPEG, PNG, and WebP
  async function verifyImageMagicBytes(file) {
    if (!file || typeof file.slice !== 'function') return false;
    const buffer = await file.slice(0, 12).arrayBuffer();
    const bytes = new Uint8Array(buffer);
    if (bytes.length < 12) return false;
    // JPEG: FF D8 FF
    const isJpeg = bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
    // PNG: 89 50 4E 47 0D 0A 1A 0A
    const isPng =
      bytes[0] === 0x89 &&
      bytes[1] === 0x50 &&
      bytes[2] === 0x4e &&
      bytes[3] === 0x47 &&
      bytes[4] === 0x0d &&
      bytes[5] === 0x0a &&
      bytes[6] === 0x1a &&
      bytes[7] === 0x0a;
    // WebP: "RIFF" (52 49 46 46) at 0..3 and "WEBP" (57 45 42 50) at 8..11
    const isWebp =
      bytes[0] === 0x52 &&
      bytes[1] === 0x49 &&
      bytes[2] === 0x46 &&
      bytes[3] === 0x46 &&
      bytes[8] === 0x57 &&
      bytes[9] === 0x45 &&
      bytes[10] === 0x42 &&
      bytes[11] === 0x50;
    return isJpeg || isPng || isWebp;
  }

  // Dynamically load official Firebase Compat SDKs from Google CDN with Subresource Integrity (SRI)
  function loadScript(src, integrity) {
    return new Promise((resolve, reject) => {
      if (document.querySelector(`script[src="${src}"]`)) {
        resolve();
        return;
      }
      const s = document.createElement('script');
      s.src = src;
      if (integrity) {
        s.integrity = integrity;
        s.crossOrigin = 'anonymous';
        s.referrerPolicy = 'no-referrer';
      }
      s.onload = resolve;
      s.onerror = reject;
      document.head.appendChild(s);
    });
  }

  async function ensureFirebaseInitialized() {
    const cfg = getRuntimeConfig();
    if (!cfg.apiKey || !cfg.projectId) {
      return false;
    }

    await loadScript(
      'https://www.gstatic.com/firebasejs/10.12.2/firebase-app-compat.js',
      'sha384-AQ3POAMqIhwS81FrUH95ekxqBZHeP5tG2JfEL3+7GuTtfRLWnrRh32UxwzM+//A9'
    );
    await loadScript(
      'https://www.gstatic.com/firebasejs/10.12.2/firebase-auth-compat.js',
      'sha384-TnlRYaR4JYz/lpaGuaiU61PjNberSA4vjLjtF+oRC/IkohkJqnWxw5EmDSOt1vA1'
    );
    await loadScript(
      'https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore-compat.js',
      'sha384-qn4Jh88HhJA8dplNQyGjOh9OGI4izVhrfj/qIFgaKcdgOE06pXqIKGlsCILZcLAC'
    );
    await loadScript(
      'https://www.gstatic.com/firebasejs/10.12.2/firebase-storage-compat.js',
      'sha384-6I0gWsz4FIAr30c0TxIxJnPQuJiZ1FfILdZrgJdjxTH3R8dgPGTvexbyqTvReV6Z'
    );

    if (!window.firebase) return false;

    if (!window.firebase.apps.length) {
      firebaseApp = window.firebase.initializeApp({
        apiKey: cfg.apiKey,
        authDomain: cfg.authDomain || `${cfg.projectId}.firebaseapp.com`,
        projectId: cfg.projectId,
        storageBucket: cfg.storageBucket || `${cfg.projectId}.appspot.com`
      });
    } else {
      firebaseApp = window.firebase.app();
    }

    firebaseAuth = window.firebase.auth();
    firebaseDb = window.firebase.firestore();
    firebaseStorage = window.firebase.storage();

    firebaseAuth.onAuthStateChanged((user) => {
      currentUser = user;
      renderAdminState();
    });

    return true;
  }

  // Client-side Canvas Image Compression & Preview
  function compressAndPreviewImage(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const img = new Image();
        img.onload = () => {
          const MAX_DIM = 1920;
          let width = img.width;
          let height = img.height;
          if (width > MAX_DIM || height > MAX_DIM) {
            if (width > height) {
              height = Math.round((height * MAX_DIM) / width);
              width = MAX_DIM;
            } else {
              width = Math.round((width * MAX_DIM) / height);
              height = MAX_DIM;
            }
          }
          const canvas = document.createElement('canvas');
          canvas.width = width;
          canvas.height = height;
          const ctx = canvas.getContext('2d');
          ctx.drawImage(img, 0, 0, width, height);

          const outputMime = file.type === 'image/png' ? 'image/png' : 'image/jpeg';
          const dataUrl = canvas.toDataURL(outputMime, 0.86);
          canvas.toBlob(
            (blob) => {
              resolve({ blob: blob || file, dataUrl, width, height });
            },
            outputMime,
            0.86
          );
        };
        img.onerror = reject;
        img.src = e.target.result;
      };
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }

  // Shared helper to validate an image file before compression
  async function validateAndCompressFile(file, inputEl) {
    if (!ALLOWED_MIME_TYPES.includes(file.type)) {
      if (inputEl) inputEl.value = '';
      showAdminAlert(
        `資安攔截：禁止上傳 "${escapeHtml(file.type || '未知格式')}"！僅允許 image/jpeg, image/png, image/webp。`,
        true
      );
      return null;
    }

    if (file.size >= MAX_UPLOAD_SIZE_BYTES) {
      if (inputEl) inputEl.value = '';
      showAdminAlert(
        `資安攔截：檔案大小 (${(file.size / 1024 / 1024).toFixed(2)} MB) 超過 5MB 上限！`,
        true
      );
      return null;
    }

    const validSignature = await verifyImageMagicBytes(file);
    if (!validSignature) {
      if (inputEl) inputEl.value = '';
      showAdminAlert(
        '資安攔截：檔案二進位標頭 (Magic Bytes) 驗證失敗！禁止偽造副檔名之非圖檔上傳。',
        true
      );
      return null;
    }

    const cleanName = sanitizeFileName(file.name);
    try {
      const result = await compressAndPreviewImage(file);
      return {
        cleanName,
        blob: result.blob,
        dataUrl: result.dataUrl,
        width: result.width,
        height: result.height
      };
    } catch (err) {
      if (inputEl) inputEl.value = '';
      showAdminAlert('圖片解析失敗，請確認檔案為有效圖檔。', true);
      return null;
    }
  }

  function buildAdminModalDom() {
    const mount = document.getElementById('stealthAdminMount');
    if (!mount || document.getElementById('stealthAdminModal')) return;

    mount.innerHTML = `
      <!-- Main Stealth Admin Modal -->
      <div id="stealthAdminModal" class="fixed inset-0 z-50 hidden bg-black/85 backdrop-blur-md flex items-center justify-center p-4 overflow-y-auto">
        <div class="relative w-full max-w-4xl bg-neutral-950 border border-neutral-800 text-white shadow-2xl my-8 overflow-hidden">
          <!-- Header -->
          <div class="flex items-center justify-between px-6 py-4 bg-neutral-900 border-b border-neutral-800">
            <div class="flex items-center gap-3">
              <span class="w-2.5 h-2.5 rounded-full bg-emerald-400"></span>
              <div>
                <h2 class="text-sm sm:text-base font-medium tracking-wider uppercase">Stealth SecOps Admin Portal｜隱藏式高安全照片管理後台</h2>
                <p class="text-[11px] text-neutral-400">Firebase Auth + Admin UID Whitelist + MIME/Size Guard (< 5MB, JPEG/PNG/WebP)</p>
              </div>
            </div>
            <button id="closeAdminModalBtn" type="button" class="border border-neutral-700 hover:border-white text-neutral-300 hover:text-white text-xs px-3 py-1.5 tracking-widest uppercase transition">
              ✕ 關閉後台
            </button>
          </div>

          <div class="p-6 max-h-[82vh] overflow-y-auto space-y-6">
            <!-- Status Banner -->
            <div id="adminStatusAlert" class="hidden p-4 border text-xs leading-relaxed"></div>

            <!-- Section 1: Firebase Connection & Admin UID Whitelist Configuration -->
            <details id="firebaseConfigDetails" open class="border border-neutral-800 bg-neutral-900/50 p-4">
              <summary class="cursor-pointer text-xs tracking-widest uppercase text-amber-400 font-medium flex items-center justify-between">
                <span>⚙️ Firebase 雲端連線金鑰輸入（僅暫存於當次分頁記憶體，關閉分頁自動銷毀）</span>
                <span class="text-neutral-400 text-[11px]">點擊展開 / 收合</span>
              </summary>
              <div class="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                <div class="sm:col-span-2">
                  <label class="block text-amber-300 font-medium mb-1">🔑 Firebase Web API Key（必填：僅暫存於本次分頁 sessionStorage，關閉網頁自動清除，絕不落盤）</label>
                  <input id="cfgApiKey" type="password" autocomplete="off" placeholder="請貼入您的 Firebase Web API Key 即可連線登入" class="w-full bg-neutral-950 border border-amber-500/60 px-3 py-2 text-white focus:border-amber-400 outline-none" />
                </div>
                <div>
                  <label class="block text-neutral-400 mb-1">Firebase Project ID（已預填）</label>
                  <input id="cfgProjectId" type="text" placeholder="orderseefoo" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white focus:border-amber-400 outline-none" />
                </div>
                <div>
                  <label class="block text-neutral-400 mb-1">Auth Domain（已預填）</label>
                  <input id="cfgAuthDomain" type="text" placeholder="orderseefoo.firebaseapp.com" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white focus:border-amber-400 outline-none" />
                </div>
                <div>
                  <label class="block text-neutral-400 mb-1">Storage Bucket（已預填）</label>
                  <input id="cfgStorageBucket" type="text" placeholder="orderseefoo.firebasestorage.app" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white focus:border-amber-400 outline-none" />
                </div>
                <div>
                  <label class="block text-neutral-400 mb-1">管理員專屬 UID 白名單（已預填）</label>
                  <input id="cfgAdminUids" type="text" placeholder="GxxxNnuuMTbRN16P5Qzvl8nlJzC3" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white focus:border-amber-400 outline-none font-mono" />
                </div>
                <div class="sm:col-span-2 flex items-center justify-between pt-2 gap-2">
                  <button id="wipeSessionKeyBtn" type="button" class="border border-neutral-700 hover:border-red-400 text-neutral-400 hover:text-red-300 px-3.5 py-2 text-xs tracking-wider uppercase transition">
                    🧹 立即清除記憶體金鑰並登出
                  </button>
                  <button id="saveFirebaseCfgBtn" type="button" class="bg-amber-500 hover:bg-amber-400 text-neutral-950 font-bold px-5 py-2 text-xs tracking-wider uppercase transition">
                    套用金鑰並連線 Firebase
                  </button>
                </div>
              </div>
            </details>

            <!-- Section 2: Authentication Gate -->
            <div id="adminAuthSection" class="border border-neutral-800 bg-neutral-900/40 p-5">
              <div id="authLoggedOutView" class="space-y-4">
                <div class="text-xs text-neutral-300">
                  🔒 <strong>雙重資安驗證閘門</strong>：請使用已驗證信箱（<code>email_verified == true</code>）且列入上方 <code>ADMIN_UID_WHITELIST</code> 之管理員帳號登入。
                </div>
                <div class="flex flex-wrap gap-3">
                  <button id="googleSignInBtn" type="button" class="border border-white bg-white text-neutral-900 hover:bg-neutral-200 px-5 py-2.5 text-xs font-medium tracking-wider uppercase transition">
                    使用 Google OAuth 驗證登入
                  </button>
                </div>
                <div class="pt-3 border-t border-neutral-800 grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                  <input id="adminEmailInput" type="email" placeholder="管理員 Email" class="bg-neutral-950 border border-neutral-800 px-3 py-2 text-white outline-none" />
                  <input id="adminPasswordInput" type="password" placeholder="密碼 (僅透過 Firebase Auth 驗證)" class="bg-neutral-950 border border-neutral-800 px-3 py-2 text-white outline-none" />
                  <button id="emailSignInBtn" type="button" class="border border-neutral-700 bg-neutral-800 hover:bg-neutral-700 text-white px-4 py-2 tracking-wider uppercase transition">
                    Email 驗證登入
                  </button>
                </div>
              </div>

              <div id="authLoggedInView" class="hidden flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div class="text-xs space-y-1">
                  <div class="text-emerald-400 font-medium">✓ 已通過 Firebase Auth 驗證</div>
                  <div class="text-neutral-300">登入信箱：<span id="adminUserEmail" class="font-mono"></span></div>
                  <div class="text-neutral-400">您的 UID：<code id="adminUserUid" class="bg-neutral-950 px-2 py-0.5 border border-neutral-800 text-amber-300 select-all"></code></div>
                  <div id="adminWhitelistBadge" class="text-[11px]"></div>
                </div>
                <button id="adminSignOutBtn" type="button" class="border border-neutral-700 hover:border-red-400 text-neutral-300 hover:text-red-300 text-xs px-4 py-2 tracking-wider uppercase transition self-start">
                  登出帳號
                </button>
              </div>
            </div>

            <!-- Section 3: Protected Photo Upload & Gallery Management -->
            <div id="adminProtectedWorkspace" class="space-y-6">
              <!-- Upload Form -->
              <div class="border border-neutral-800 bg-neutral-900/40 p-5 space-y-4">
                <h3 class="text-xs tracking-[0.2em] uppercase text-amber-400 font-medium">
                  ➕ 新增展示照片（嚴格限制 JPEG / PNG / WebP，單檔 &lt; 5MB，自動清洗檔名與壓縮）
                </h3>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                  <div class="sm:col-span-2">
                    <label class="block text-neutral-400 mb-1">選擇圖片檔案 (僅限 .jpg, .png, .webp，上限 5MB)</label>
                    <input id="photoFileInput" type="file" accept="image/jpeg,image/png,image/webp" class="w-full bg-neutral-950 border border-neutral-800 p-2 text-neutral-300" />
                  </div>

                  <div id="uploadPreviewBox" class="hidden sm:col-span-2 border border-neutral-800 bg-neutral-950 p-3 flex items-center gap-4">
                    <img id="uploadPreviewImg" alt="Upload Preview" class="w-28 h-20 object-cover border border-neutral-800" />
                    <div class="text-[11px] text-neutral-400 space-y-1">
                      <div>清洗後安全檔名：<span id="uploadCleanName" class="text-emerald-400 font-mono"></span></div>
                      <div>壓縮後大小與尺寸：<span id="uploadCompressedInfo" class="text-neutral-200"></span></div>
                    </div>
                  </div>

                  <div>
                    <label class="block text-neutral-400 mb-1">分類 (Category)</label>
                    <select id="photoCategorySelect" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white outline-none">
                      <option value="interior">室內與平面圖 (interior)</option>
                      <option value="exterior">外觀、公園與停車場 (exterior)</option>
                    </select>
                  </div>

                  <div>
                    <label class="block text-neutral-400 mb-1">排序權重 (Order，數字越小越前面)</label>
                    <input id="photoOrderInput" type="number" value="8" min="1" max="999" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white outline-none" />
                  </div>

                  <div>
                    <label class="block text-neutral-400 mb-1">繁中標籤 (Tag zh-TW)</label>
                    <input id="photoTagZhInput" type="text" maxlength="40" placeholder="例如：挑高 4.6m 室內" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white outline-none" />
                  </div>

                  <div>
                    <label class="block text-neutral-400 mb-1">英文標籤 (Tag en-US)</label>
                    <input id="photoTagEnInput" type="text" maxlength="40" placeholder="e.g., 4.6m High Interior" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white outline-none" />
                  </div>

                  <div>
                    <label class="block text-neutral-400 mb-1">繁中標題 (Title zh-TW)</label>
                    <input id="photoTitleZhInput" type="text" maxlength="120" placeholder="請輸入繁體中文照片標題" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white outline-none" />
                  </div>

                  <div>
                    <label class="block text-neutral-400 mb-1">英文標題 (Title en-US)</label>
                    <input id="photoTitleEnInput" type="text" maxlength="120" placeholder="Enter English photo title" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white outline-none" />
                  </div>

                  <div>
                    <label class="block text-neutral-400 mb-1">繁中圖說 (Caption zh-TW)</label>
                    <input id="photoDescZhInput" type="text" maxlength="200" placeholder="請輸入繁體中文說明" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white outline-none" />
                  </div>

                  <div>
                    <label class="block text-neutral-400 mb-1">英文圖說 (Caption en-US)</label>
                    <input id="photoDescEnInput" type="text" maxlength="200" placeholder="Enter English description" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white outline-none" />
                  </div>
                </div>

                <div class="flex justify-end pt-2">
                  <button id="uploadPhotoSubmitBtn" type="button" class="bg-white hover:bg-neutral-200 text-neutral-950 font-bold px-6 py-2.5 text-xs tracking-widest uppercase transition">
                    安全驗證並上傳新增照片
                  </button>
                </div>
              </div>

              <!-- Current Gallery List -->
              <div class="border border-neutral-800 bg-neutral-900/40 p-5 space-y-4">
                <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <h3 class="text-xs tracking-[0.2em] uppercase text-neutral-200 font-medium">
                      🖼️ 目前前台展示照片清單（支援單張編輯、排序、刪除與雲端同步）
                    </h3>
                    <p class="text-[11px] text-neutral-400 mt-1">
                      點擊「✏️ 編輯」可修改任一照片的中英文標題、圖說、標籤、分類、排序或更換圖檔；所有變更將自動同步至雲端讓所有訪客立即看到。
                    </p>
                  </div>
                  <div class="flex flex-wrap items-center gap-2 shrink-0">
                    <button id="syncCurrentListCloudBtn" type="button" class="bg-amber-500 hover:bg-amber-400 text-neutral-950 font-bold px-3.5 py-1.5 text-[11px] tracking-wider uppercase transition">
                      ☁️ 同步發布目前清單至雲端
                    </button>
                    <button id="resetDefaultPhotosBtn" type="button" class="border border-neutral-700 hover:border-white text-neutral-300 hover:text-white px-3 py-1.5 text-[11px] tracking-wider transition">
                      還原預設 7 張圖庫
                    </button>
                  </div>
                </div>
                <div id="adminPhotoListContainer" class="space-y-2.5"></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Edit Photo Modal -->
      <div id="editPhotoModal" class="fixed inset-0 z-50 hidden bg-black/90 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
        <div class="max-w-2xl w-full bg-neutral-950 border border-amber-500/60 p-6 text-white shadow-2xl space-y-4 my-8">
          <div class="flex items-center justify-between border-b border-neutral-800 pb-3">
            <div class="text-xs tracking-widest uppercase text-amber-400 font-bold">
              ✏️ 編輯前台展示照片資訊 (Edit Gallery Photo)
            </div>
            <span id="editPhotoIdBadge" class="text-[11px] font-mono text-neutral-400 bg-neutral-900 px-2 py-0.5 border border-neutral-800"></span>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div class="sm:col-span-2 flex items-center gap-4 bg-neutral-900/60 p-3 border border-neutral-800">
              <img id="editPhotoCurrentThumb" alt="Current Photo" class="w-28 h-20 object-cover border border-neutral-700 shrink-0" />
              <div class="space-y-1.5 flex-1">
                <label class="block text-neutral-300 font-medium">更換照片圖檔（選填：不選則保留原圖，支援 JPEG/PNG/WebP &lt; 5MB）</label>
                <input id="editPhotoFileInput" type="file" accept="image/jpeg,image/png,image/webp" class="w-full bg-neutral-950 border border-neutral-800 p-1.5 text-neutral-300 text-[11px]" />
                <div id="editPhotoReplaceStatus" class="text-[11px] text-emerald-400 hidden"></div>
              </div>
            </div>

            <div>
              <label class="block text-neutral-400 mb-1">分類 (Category)</label>
              <select id="editPhotoCategorySelect" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white outline-none">
                <option value="interior">室內與平面圖 (interior)</option>
                <option value="exterior">外觀、公園與停車場 (exterior)</option>
              </select>
            </div>

            <div>
              <label class="block text-neutral-400 mb-1">排序權重 (Order，數字越小越前面)</label>
              <input id="editPhotoOrderInput" type="number" min="1" max="999" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white outline-none" />
            </div>

            <div>
              <label class="block text-neutral-400 mb-1">繁中標籤 (Tag zh-TW，上限 40 字)</label>
              <input id="editPhotoTagZhInput" type="text" maxlength="40" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white outline-none" />
            </div>

            <div>
              <label class="block text-neutral-400 mb-1">英文標籤 (Tag en-US，上限 40 字)</label>
              <input id="editPhotoTagEnInput" type="text" maxlength="40" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white outline-none" />
            </div>

            <div>
              <label class="block text-neutral-400 mb-1">繁中標題 (Title zh-TW，上限 120 字)</label>
              <input id="editPhotoTitleZhInput" type="text" maxlength="120" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white outline-none" />
            </div>

            <div>
              <label class="block text-neutral-400 mb-1">英文標題 (Title en-US，上限 120 字)</label>
              <input id="editPhotoTitleEnInput" type="text" maxlength="120" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white outline-none" />
            </div>

            <div class="sm:col-span-2">
              <label class="block text-neutral-400 mb-1">繁中圖說 (Caption zh-TW，上限 200 字)</label>
              <input id="editPhotoDescZhInput" type="text" maxlength="200" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white outline-none" />
            </div>

            <div class="sm:col-span-2">
              <label class="block text-neutral-400 mb-1">英文圖說 (Caption en-US，上限 200 字)</label>
              <input id="editPhotoDescEnInput" type="text" maxlength="200" class="w-full bg-neutral-950 border border-neutral-800 px-3 py-2 text-white outline-none" />
            </div>
          </div>

          <div class="flex items-center justify-end gap-3 pt-3 border-t border-neutral-800">
            <button id="cancelEditPhotoBtn" type="button" class="border border-neutral-700 hover:border-white text-neutral-300 text-xs px-4 py-2 tracking-wider uppercase">
              取消
            </button>
            <button id="saveEditPhotoBtn" type="button" class="bg-amber-500 hover:bg-amber-400 text-neutral-950 text-xs font-bold px-5 py-2 tracking-wider uppercase">
              💾 儲存修改並同步至雲端
            </button>
          </div>
        </div>
      </div>

      <!-- Secondary Confirmation Modal for Photo Deletion -->
      <div id="deleteConfirmModal" class="fixed inset-0 z-50 hidden bg-black/90 backdrop-blur-sm flex items-center justify-center p-4">
        <div class="max-w-md w-full bg-neutral-950 border border-red-500/60 p-6 text-white shadow-2xl space-y-4">
          <div class="text-xs tracking-widest uppercase text-red-400 font-bold">⚠️ 二次安全確認 (Secondary Deletion Confirmation)</div>
          <p class="text-sm text-neutral-200 font-light leading-relaxed">
            您確定要永久移除此張展示照片嗎？此操作將同步刪除 Cloud Storage 實體圖檔與更新 Firestore <code>gallery_photos</code> 雲端清單，並立即更新前台畫廊。
          </p>
          <div id="deleteConfirmPhotoTitle" class="text-xs font-mono bg-neutral-900 p-3 border border-neutral-800 text-amber-300"></div>
          <div class="flex items-center justify-end gap-3 pt-2">
            <button id="cancelDeletePhotoBtn" type="button" class="border border-neutral-700 hover:border-white text-neutral-300 text-xs px-4 py-2 tracking-wider uppercase">
              取消
            </button>
            <button id="confirmDeletePhotoBtn" type="button" class="bg-red-600 hover:bg-red-500 text-white text-xs font-bold px-5 py-2 tracking-wider uppercase">
              確認同步刪除
            </button>
          </div>
        </div>
      </div>
    `;

    bindAdminEvents();
    populateConfigInputs();
    renderAdminPhotoList();
  }

  function showAdminAlert(message, isError) {
    const alertEl = document.getElementById('adminStatusAlert');
    if (!alertEl) return;
    alertEl.className = isError
      ? 'p-4 border border-red-500/60 bg-red-950/40 text-red-200 text-xs leading-relaxed'
      : 'p-4 border border-emerald-500/60 bg-emerald-950/40 text-emerald-200 text-xs leading-relaxed';
    alertEl.textContent = message;
    alertEl.classList.remove('hidden');
  }

  function populateConfigInputs() {
    const cfg = getRuntimeConfig();
    const apiKeyEl = document.getElementById('cfgApiKey');
    const projIdEl = document.getElementById('cfgProjectId');
    const authDomEl = document.getElementById('cfgAuthDomain');
    const bucketEl = document.getElementById('cfgStorageBucket');
    const uidsEl = document.getElementById('cfgAdminUids');

    if (apiKeyEl) apiKeyEl.value = cfg.apiKey || '';
    if (projIdEl) projIdEl.value = cfg.projectId || '';
    if (authDomEl) authDomEl.value = cfg.authDomain || '';
    if (bucketEl) bucketEl.value = cfg.storageBucket || '';
    if (uidsEl) {
      uidsEl.value = Array.isArray(cfg.adminUidWhitelist) ? cfg.adminUidWhitelist.join(', ') : '';
    }
  }

  function renderAdminState() {
    const cfg = getRuntimeConfig();
    const outView = document.getElementById('authLoggedOutView');
    const inView = document.getElementById('authLoggedInView');
    const emailSpan = document.getElementById('adminUserEmail');
    const uidCode = document.getElementById('adminUserUid');
    const badge = document.getElementById('adminWhitelistBadge');
    const workspace = document.getElementById('adminProtectedWorkspace');
    const authorized = isUserAuthorizedAdmin(currentUser, cfg);

    if (workspace) {
      if (authorized) {
        workspace.classList.remove('opacity-50', 'pointer-events-none');
      } else {
        workspace.classList.add('opacity-50', 'pointer-events-none');
      }
    }

    if (currentUser) {
      if (outView) outView.classList.add('hidden');
      if (inView) inView.classList.remove('hidden');
      if (emailSpan) emailSpan.textContent = `${currentUser.email || 'N/A'} (email_verified: ${currentUser.emailVerified})`;
      if (uidCode) uidCode.textContent = currentUser.uid;

      if (badge) {
        if (authorized) {
          badge.className = 'text-[11px] text-emerald-400 font-bold';
          badge.textContent = '✓ UID 白名單雙重查驗通過（具備雲端寫入、編輯與刪除權限）';
        } else {
          badge.className = 'text-[11px] text-amber-300';
          badge.textContent =
            '⚠️ 您的 UID 尚未加入上方「管理員專屬 UID 白名單」，請複製上方 UID 貼入白名單欄位並點擊儲存。';
        }
      }
    } else {
      if (outView) outView.classList.remove('hidden');
      if (inView) inView.classList.add('hidden');
    }

    renderAdminPhotoList();
  }

  function renderAdminPhotoList() {
    const container = document.getElementById('adminPhotoListContainer');
    if (!container || !window.TCStorefrontGallery) return;

    const photos = window.TCStorefrontGallery.getPhotos();
    container.innerHTML = '';

    photos.forEach((photo, idx) => {
      const row = document.createElement('div');
      row.className =
        'flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 bg-neutral-950 border border-neutral-800 text-xs';

      const left = document.createElement('div');
      left.className = 'flex items-center gap-3';

      const thumb = document.createElement('img');
      thumb.src = sanitizeImageUrl(photo.src);
      thumb.alt = photo.title_zh || '';
      thumb.className = 'w-16 h-12 object-cover border border-neutral-800 shrink-0';

      const info = document.createElement('div');
      info.className = 'space-y-0.5';

      const titleLine = document.createElement('div');
      titleLine.className = 'font-medium text-white';
      titleLine.textContent = `[#${photo.order || idx + 1}] ${photo.title_zh || ''} / ${photo.title_en || ''}`;

      const subLine = document.createElement('div');
      subLine.className = 'text-[11px] text-neutral-400';
      subLine.textContent = `分類: ${photo.category === 'exterior' ? '外觀 (exterior)' : '室內 (interior)'} ｜ 標籤: ${photo.tag_zh || ''} / ${photo.tag_en || ''}`;

      const descLine = document.createElement('div');
      descLine.className = 'text-[11px] text-neutral-500 line-clamp-1';
      descLine.textContent = photo.desc_zh || photo.desc_en || '';

      info.appendChild(titleLine);
      info.appendChild(subLine);
      if (photo.desc_zh || photo.desc_en) {
        info.appendChild(descLine);
      }
      left.appendChild(thumb);
      left.appendChild(info);

      const actions = document.createElement('div');
      actions.className = 'flex flex-wrap items-center gap-1.5 shrink-0';

      const editBtn = document.createElement('button');
      editBtn.type = 'button';
      editBtn.className =
        'border border-amber-500/60 hover:bg-amber-500 hover:text-neutral-950 text-amber-300 px-2.5 py-1 text-[11px] font-medium transition';
      editBtn.textContent = '✏️ 編輯';
      editBtn.addEventListener('click', () => openEditPhotoModal(photo, idx));

      const upBtn = document.createElement('button');
      upBtn.type = 'button';
      upBtn.className = 'border border-neutral-700 hover:border-white px-2.5 py-1 text-[11px] text-neutral-300';
      upBtn.textContent = '↑ 上移';
      upBtn.addEventListener('click', () => movePhotoOrder(idx, -1));

      const downBtn = document.createElement('button');
      downBtn.type = 'button';
      downBtn.className = 'border border-neutral-700 hover:border-white px-2.5 py-1 text-[11px] text-neutral-300';
      downBtn.textContent = '↓ 下移';
      downBtn.addEventListener('click', () => movePhotoOrder(idx, 1));

      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className =
        'border border-red-500/50 hover:bg-red-600 hover:text-white text-red-300 px-2.5 py-1 text-[11px] transition';
      delBtn.textContent = '刪除';
      delBtn.addEventListener('click', () => openDeleteConfirmModal(photo));

      actions.appendChild(editBtn);
      actions.appendChild(upBtn);
      actions.appendChild(downBtn);
      actions.appendChild(delBtn);

      row.appendChild(left);
      row.appendChild(actions);
      container.appendChild(row);
    });
  }

  function openEditPhotoModal(photo, idx) {
    const cfg = getRuntimeConfig();
    if (!isUserAuthorizedAdmin(currentUser, cfg)) {
      showAdminAlert('拒絕存取：請先通過 Firebase Auth 驗證且確認 UID 已列入白名單！', true);
      return;
    }

    editingPhotoTarget = { ...photo, _idx: idx };
    editReplacementBlob = null;
    editReplacementDataUrl = null;
    editReplacementFileName = '';

    const modal = document.getElementById('editPhotoModal');
    const idBadge = document.getElementById('editPhotoIdBadge');
    const thumb = document.getElementById('editPhotoCurrentThumb');
    const fileInput = document.getElementById('editPhotoFileInput');
    const replaceStatus = document.getElementById('editPhotoReplaceStatus');
    const catSelect = document.getElementById('editPhotoCategorySelect');
    const orderInput = document.getElementById('editPhotoOrderInput');
    const tagZhInput = document.getElementById('editPhotoTagZhInput');
    const tagEnInput = document.getElementById('editPhotoTagEnInput');
    const titleZhInput = document.getElementById('editPhotoTitleZhInput');
    const titleEnInput = document.getElementById('editPhotoTitleEnInput');
    const descZhInput = document.getElementById('editPhotoDescZhInput');
    const descEnInput = document.getElementById('editPhotoDescEnInput');

    if (idBadge) idBadge.textContent = `ID: ${photo.id || 'item_' + (idx + 1)}`;
    if (thumb) thumb.src = sanitizeImageUrl(photo.src);
    if (fileInput) fileInput.value = '';
    if (replaceStatus) {
      replaceStatus.textContent = '';
      replaceStatus.classList.add('hidden');
    }
    if (catSelect) catSelect.value = photo.category === 'exterior' ? 'exterior' : 'interior';
    if (orderInput) orderInput.value = photo.order || idx + 1;
    if (tagZhInput) tagZhInput.value = photo.tag_zh || '';
    if (tagEnInput) tagEnInput.value = photo.tag_en || '';
    if (titleZhInput) titleZhInput.value = photo.title_zh || '';
    if (titleEnInput) titleEnInput.value = photo.title_en || '';
    if (descZhInput) descZhInput.value = photo.desc_zh || '';
    if (descEnInput) descEnInput.value = photo.desc_en || '';

    if (modal) modal.classList.remove('hidden');
  }

  function closeEditPhotoModal() {
    editingPhotoTarget = null;
    editReplacementBlob = null;
    editReplacementDataUrl = null;
    editReplacementFileName = '';
    const modal = document.getElementById('editPhotoModal');
    if (modal) modal.classList.add('hidden');
  }

  async function saveEditedPhoto() {
    if (!editingPhotoTarget || !window.TCStorefrontGallery) return;
    const cfg = getRuntimeConfig();
    if (!isUserAuthorizedAdmin(currentUser, cfg)) {
      closeEditPhotoModal();
      showAdminAlert('拒絕存取：請先通過 Firebase Auth 驗證且確認 UID 已列入白名單！', true);
      return;
    }

    const category = document.getElementById('editPhotoCategorySelect').value === 'exterior' ? 'exterior' : 'interior';
    const order = parseInt(document.getElementById('editPhotoOrderInput').value || '1', 10) || 1;
    const tag_zh = (document.getElementById('editPhotoTagZhInput').value || '').trim().slice(0, 40);
    const tag_en = (document.getElementById('editPhotoTagEnInput').value || '').trim().slice(0, 40);
    const title_zh = (document.getElementById('editPhotoTitleZhInput').value || '').trim().slice(0, 120);
    const title_en = (document.getElementById('editPhotoTitleEnInput').value || '').trim().slice(0, 120);
    const desc_zh = (document.getElementById('editPhotoDescZhInput').value || '').trim().slice(0, 200);
    const desc_en = (document.getElementById('editPhotoDescEnInput').value || '').trim().slice(0, 200);

    if (!title_zh || !title_en) {
      showAdminAlert('請填寫照片的「繁中標題」與「英文標題」。', true);
      return;
    }

    const saveBtn = document.getElementById('saveEditPhotoBtn');
    if (saveBtn) {
      saveBtn.disabled = true;
      saveBtn.textContent = '雲端同步中...';
    }

    try {
      let updatedSrc = editingPhotoTarget.src;
      let updatedStoragePath = editingPhotoTarget.storagePath || '';

      // If admin selected a replacement image file, upload to Cloud Storage first
      if (editReplacementBlob && firebaseStorage) {
        const newStoragePath = `gallery_photos/${editReplacementFileName}`;
        const storageRef = firebaseStorage.ref(newStoragePath);
        await storageRef.put(editReplacementBlob, {
          contentType: editReplacementBlob.type || 'image/jpeg'
        });
        updatedSrc = await storageRef.getDownloadURL();

        // Optionally clean up old Cloud Storage object if it was a custom uploaded file
        if (updatedStoragePath && updatedStoragePath !== newStoragePath) {
          try {
            await firebaseStorage.ref(updatedStoragePath).delete();
          } catch (e) {}
        }
        updatedStoragePath = newStoragePath;
      }

      const list = window.TCStorefrontGallery.getPhotos();
      const targetIndex = list.findIndex(
        (p, i) => (p.id && p.id === editingPhotoTarget.id) || i === editingPhotoTarget._idx
      );
      if (targetIndex === -1) {
        closeEditPhotoModal();
        return;
      }

      const updatedItem = normalizePhotoForFirestore(
        {
          ...list[targetIndex],
          src: updatedSrc,
          storagePath: updatedStoragePath,
          category,
          order,
          tag_zh,
          tag_en,
          title_zh,
          title_en,
          desc_zh,
          desc_en
        },
        targetIndex,
        currentUser ? currentUser.uid : ''
      );

      list[targetIndex] = updatedItem;
      list.sort((a, b) => (a.order || 99) - (b.order || 99));
      list.forEach((item, i) => {
        item.order = i + 1;
      });

      const syncRes = await syncEntireGalleryListToFirestore(list);
      const finalPhotos = syncRes.synced ? syncRes.normalizedList : list;

      try {
        localStorage.setItem('tcstorefront_gallery_cache', JSON.stringify(finalPhotos));
      } catch (e) {}

      window.TCStorefrontGallery.updatePhotos(finalPhotos);
      closeEditPhotoModal();
      renderAdminPhotoList();
      showAdminAlert(
        `✓ 已成功儲存「${updatedItem.title_zh}」的修改，並將全清單（共 ${finalPhotos.length} 張）同步發布至 Firebase 雲端！`,
        false
      );
    } catch (err) {
      showAdminAlert(`儲存或雲端同步失敗：${err.message}`, true);
    } finally {
      if (saveBtn) {
        saveBtn.disabled = false;
        saveBtn.textContent = '💾 儲存修改並同步至雲端';
      }
    }
  }

  async function movePhotoOrder(index, direction) {
    const cfg = getRuntimeConfig();
    if (!isUserAuthorizedAdmin(currentUser, cfg)) {
      showAdminAlert('拒絕存取：請先通過 Firebase Auth 驗證且確認 UID 已列入白名單！', true);
      return;
    }
    if (!window.TCStorefrontGallery) return;
    const list = window.TCStorefrontGallery.getPhotos();
    const targetIdx = index + direction;
    if (targetIdx < 0 || targetIdx >= list.length) return;

    const temp = list[index];
    list[index] = list[targetIdx];
    list[targetIdx] = temp;

    list.forEach((item, i) => {
      item.order = i + 1;
    });

    try {
      localStorage.setItem('tcstorefront_gallery_cache', JSON.stringify(list));
    } catch (e) {}

    window.TCStorefrontGallery.updatePhotos(list);
    renderAdminPhotoList();

    try {
      const syncRes = await syncEntireGalleryListToFirestore(list);
      if (syncRes.synced) {
        showAdminAlert('✓ 照片排序已更新並自動同步至 Firebase 雲端！', false);
      }
    } catch (err) {
      showAdminAlert(`本機排序已更新，但雲端同步失敗：${err.message}`, true);
    }
  }

  function openDeleteConfirmModal(photo) {
    const cfg = getRuntimeConfig();
    if (!isUserAuthorizedAdmin(currentUser, cfg)) {
      showAdminAlert('拒絕存取：請先通過 Firebase Auth 驗證且確認 UID 已列入白名單！', true);
      return;
    }
    pendingDeletePhoto = photo;
    const modal = document.getElementById('deleteConfirmModal');
    const titleBox = document.getElementById('deleteConfirmPhotoTitle');
    if (titleBox) {
      titleBox.textContent = `${photo.title_zh || ''} (${photo.id || 'item'})`;
    }
    if (modal) modal.classList.remove('hidden');
  }

  function closeDeleteConfirmModal() {
    pendingDeletePhoto = null;
    const modal = document.getElementById('deleteConfirmModal');
    if (modal) modal.classList.add('hidden');
  }

  async function executeConfirmedDeletion() {
    if (!pendingDeletePhoto || !window.TCStorefrontGallery) return;
    const cfg = getRuntimeConfig();

    if (!isUserAuthorizedAdmin(currentUser, cfg)) {
      closeDeleteConfirmModal();
      showAdminAlert(
        '拒絕存取：刪除照片必須先通過 Firebase Auth 驗證，且您的 UID 必須在 ADMIN_UID_WHITELIST 白名單內！',
        true
      );
      return;
    }

    const updated = window.TCStorefrontGallery
      .getPhotos()
      .filter((p) => p.id !== pendingDeletePhoto.id && p.src !== pendingDeletePhoto.src);

    updated.forEach((item, i) => {
      item.order = i + 1;
    });

    if (cfg.apiKey && cfg.projectId) {
      try {
        if (firebaseStorage && pendingDeletePhoto.storagePath) {
          try {
            await firebaseStorage.ref(pendingDeletePhoto.storagePath).delete();
          } catch (storageErr) {}
        }
        if (firebaseDb && pendingDeletePhoto.id) {
          await firebaseDb.collection('gallery_photos').doc(pendingDeletePhoto.id).delete();
        }
        // Sync the remaining list to Firestore so default photo deletions also persist in the cloud
        await syncEntireGalleryListToFirestore(updated);
      } catch (err) {
        closeDeleteConfirmModal();
        showAdminAlert(`雲端刪除或同步失敗（請檢查 Firebase Security Rules 權限）：${err.message}`, true);
        return;
      }
    }

    try {
      localStorage.setItem('tcstorefront_gallery_cache', JSON.stringify(updated));
    } catch (e) {}

    window.TCStorefrontGallery.updatePhotos(updated);
    closeDeleteConfirmModal();
    renderAdminPhotoList();
    showAdminAlert('✓ 照片已通過二次確認並完成雲端同步移除，前台畫廊已即時更新。', false);
  }

  function bindAdminEvents() {
    const closeBtn = document.getElementById('closeAdminModalBtn');
    const modal = document.getElementById('stealthAdminModal');
    if (closeBtn && modal) {
      closeBtn.addEventListener('click', () => modal.classList.add('hidden'));
    }

    const saveCfgBtn = document.getElementById('saveFirebaseCfgBtn');
    if (saveCfgBtn) {
      saveCfgBtn.addEventListener('click', async () => {
        const apiKey = (document.getElementById('cfgApiKey').value || '').trim();
        const projectId = (document.getElementById('cfgProjectId').value || '').trim();
        const authDomain = (document.getElementById('cfgAuthDomain').value || '').trim();
        const storageBucket = (document.getElementById('cfgStorageBucket').value || '').trim();
        const rawUids = (document.getElementById('cfgAdminUids').value || '').trim();
        const adminUidWhitelist = rawUids
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);

        saveRuntimeConfig({
          apiKey,
          projectId,
          authDomain,
          storageBucket,
          adminUidWhitelist
        });

        const ok = await ensureFirebaseInitialized();
        if (ok) {
          showAdminAlert('✓ Firebase 連線設定已載入當次記憶體（關閉分頁後自動銷毀）！現在可點擊下方按鈕登入。', false);
        } else {
          showAdminAlert('請貼入有效的 Firebase Web API Key 以啟用雲端驗證。', true);
        }
        renderAdminState();
      });
    }

    const wipeBtn = document.getElementById('wipeSessionKeyBtn');
    if (wipeBtn) {
      wipeBtn.addEventListener('click', async () => {
        if (firebaseAuth) {
          try {
            await firebaseAuth.signOut();
          } catch (e) {}
        }
        currentUser = null;
        sessionRuntimeConfig.apiKey = '';
        try {
          sessionStorage.removeItem(CONFIG_STORAGE_KEY);
          localStorage.removeItem(CONFIG_STORAGE_KEY);
        } catch (e) {}
        const apiKeyEl = document.getElementById('cfgApiKey');
        if (apiKeyEl) apiKeyEl.value = '';
        renderAdminState();
        showAdminAlert('✓ 已徹底清除瀏覽器記憶體中的 API Key 並安全登出！', false);
      });
    }

    const googleBtn = document.getElementById('googleSignInBtn');
    if (googleBtn) {
      googleBtn.addEventListener('click', async () => {
        const ready = await ensureFirebaseInitialized();
        if (!ready || !firebaseAuth) {
          showAdminAlert('請先展開上方「Firebase 雲端專案設定」填入 API Key 與 Project ID。', true);
          return;
        }
        try {
          const provider = new window.firebase.auth.GoogleAuthProvider();
          await firebaseAuth.signInWithPopup(provider);
          showAdminAlert('✓ Google OAuth 驗證成功！請確認您的 UID 已加入白名單。', false);
        } catch (err) {
          showAdminAlert(`Google OAuth 登入失敗：${err.message}`, true);
        }
      });
    }

    const emailBtn = document.getElementById('emailSignInBtn');
    if (emailBtn) {
      emailBtn.addEventListener('click', async () => {
        const ready = await ensureFirebaseInitialized();
        if (!ready || !firebaseAuth) {
          showAdminAlert('請先展開上方「Firebase 雲端專案設定」填入 API Key 與 Project ID。', true);
          return;
        }
        const email = (document.getElementById('adminEmailInput').value || '').trim();
        const pass = document.getElementById('adminPasswordInput').value || '';
        if (!email || !pass) {
          showAdminAlert('請輸入管理員 Email 與密碼。', true);
          return;
        }
        try {
          await firebaseAuth.signInWithEmailAndPassword(email, pass);
          document.getElementById('adminPasswordInput').value = '';
          showAdminAlert('✓ Email 驗證登入成功！', false);
        } catch (err) {
          showAdminAlert(`Email 登入失敗：${err.message}`, true);
        }
      });
    }

    const signOutBtn = document.getElementById('adminSignOutBtn');
    if (signOutBtn) {
      signOutBtn.addEventListener('click', async () => {
        if (firebaseAuth) {
          await firebaseAuth.signOut();
          currentUser = null;
          renderAdminState();
          showAdminAlert('已安全登出管理員帳號。', false);
        }
      });
    }

    // Pre-upload File Validation for New Photo (MIME + <5MB + Magic Bytes + Filename Sanitization + Canvas Compression)
    const fileInput = document.getElementById('photoFileInput');
    if (fileInput) {
      fileInput.addEventListener('change', async (e) => {
        const file = e.target.files && e.target.files[0];
        const previewBox = document.getElementById('uploadPreviewBox');
        if (!file) {
          if (previewBox) previewBox.classList.add('hidden');
          return;
        }

        const validated = await validateAndCompressFile(file, fileInput);
        if (!validated) return;

        sanitizedUploadFileName = validated.cleanName;
        compressedUploadBlob = validated.blob;
        compressedPreviewDataUrl = validated.dataUrl;

        const previewImg = document.getElementById('uploadPreviewImg');
        const cleanNameEl = document.getElementById('uploadCleanName');
        const infoEl = document.getElementById('uploadCompressedInfo');

        if (previewImg) previewImg.src = validated.dataUrl;
        if (cleanNameEl) cleanNameEl.textContent = sanitizedUploadFileName;
        if (infoEl) {
          infoEl.textContent = `${validated.width}×${validated.height} px ｜ ${(validated.blob.size / 1024).toFixed(1)} KB`;
        }
        if (previewBox) previewBox.classList.remove('hidden');
        showAdminAlert('✓ 圖片通過前端 MIME (< 5MB) 與安全檔名檢核，已完成客戶端壓縮預覽。', false);
      });
    }

    // Pre-upload File Validation for Replacement Photo inside Edit Modal
    const editFileInput = document.getElementById('editPhotoFileInput');
    if (editFileInput) {
      editFileInput.addEventListener('change', async (e) => {
        const file = e.target.files && e.target.files[0];
        const statusEl = document.getElementById('editPhotoReplaceStatus');
        const thumbEl = document.getElementById('editPhotoCurrentThumb');
        if (!file) {
          editReplacementBlob = null;
          editReplacementDataUrl = null;
          editReplacementFileName = '';
          if (statusEl) statusEl.classList.add('hidden');
          return;
        }

        const validated = await validateAndCompressFile(file, editFileInput);
        if (!validated) return;

        editReplacementFileName = validated.cleanName;
        editReplacementBlob = validated.blob;
        editReplacementDataUrl = validated.dataUrl;

        if (thumbEl) thumbEl.src = validated.dataUrl;
        if (statusEl) {
          statusEl.textContent = `✓ 已準備替換為新圖檔：${validated.cleanName} (${validated.width}×${validated.height} px, ${(validated.blob.size / 1024).toFixed(1)} KB)`;
          statusEl.classList.remove('hidden');
        }
      });
    }

    // Upload & Sync Handler
    const uploadBtn = document.getElementById('uploadPhotoSubmitBtn');
    if (uploadBtn) {
      uploadBtn.addEventListener('click', async () => {
        if (!compressedUploadBlob || !compressedPreviewDataUrl) {
          showAdminAlert('請先選擇符合規範的圖片檔案（JPEG / PNG / WebP，< 5MB）。', true);
          return;
        }

        const category = document.getElementById('photoCategorySelect').value === 'exterior' ? 'exterior' : 'interior';
        const order = parseInt(document.getElementById('photoOrderInput').value || '8', 10) || 8;
        const tag_zh = (document.getElementById('photoTagZhInput').value || '精選實景').trim();
        const tag_en = (document.getElementById('photoTagEnInput').value || 'Featured View').trim();
        const title_zh = (document.getElementById('photoTitleZhInput').value || '土城青雲路341號店面實景').trim();
        const title_en = (document.getElementById('photoTitleEnInput').value || 'Tucheng No. 341 Qingyun Rd. Storefront').trim();
        const desc_zh = (document.getElementById('photoDescZhInput').value || '').trim();
        const desc_en = (document.getElementById('photoDescEnInput').value || '').trim();

        const cfg = getRuntimeConfig();
        let finalSrc = '';
        let storagePath = '';
        const newDocId = 'photo_' + Date.now();

        if (cfg.apiKey && cfg.projectId) {
          if (!isUserAuthorizedAdmin(currentUser, cfg)) {
            showAdminAlert(
              '資安攔截：您尚未登入通過驗證之管理員帳號，或您的 UID 不在 ADMIN_UID_WHITELIST 白名單中！',
              true
            );
            return;
          }

          try {
            storagePath = `gallery_photos/${sanitizedUploadFileName}`;
            const storageRef = firebaseStorage.ref(storagePath);
            await storageRef.put(compressedUploadBlob, {
              contentType: compressedUploadBlob.type || 'image/jpeg'
            });
            finalSrc = await storageRef.getDownloadURL();

            const docRecord = normalizePhotoForFirestore(
              {
                id: newDocId,
                order,
                src: finalSrc,
                storagePath,
                category,
                tag_zh,
                tag_en,
                title_zh,
                title_en,
                desc_zh,
                desc_en
              },
              order - 1,
              currentUser.uid
            );

            const updatedList = [...window.TCStorefrontGallery.getPhotos(), docRecord].sort(
              (a, b) => (a.order || 99) - (b.order || 99)
            );
            updatedList.forEach((item, idx) => {
              item.order = idx + 1;
            });

            // Sync entire active list (including default photos + new photo) to Firestore
            const syncRes = await syncEntireGalleryListToFirestore(updatedList);
            const finalPhotos = syncRes.synced ? syncRes.normalizedList : updatedList;

            try {
              localStorage.setItem('tcstorefront_gallery_cache', JSON.stringify(finalPhotos));
            } catch (e) {}
            window.TCStorefrontGallery.updatePhotos(finalPhotos);
            renderAdminPhotoList();
            showAdminAlert('✓ 已成功上傳新照片，並將完整前台照片清單同步至 Firebase Cloud！', false);
          } catch (err) {
            showAdminAlert(`雲端上傳失敗（請確認 Firebase Storage / Firestore 權限規則）：${err.message}`, true);
          }
        } else {
          showAdminAlert(
            '請先展開上方「Firebase 雲端連線金鑰輸入」，完成連線與管理員登入後即可上傳雲端圖庫。',
            true
          );
        }
      });
    }

    // Edit Photo Modal Buttons
    const cancelEditBtn = document.getElementById('cancelEditPhotoBtn');
    const saveEditBtn = document.getElementById('saveEditPhotoBtn');
    if (cancelEditBtn) cancelEditBtn.addEventListener('click', closeEditPhotoModal);
    if (saveEditBtn) saveEditBtn.addEventListener('click', saveEditedPhoto);

    // Manual Cloud Sync Button
    const syncCloudBtn = document.getElementById('syncCurrentListCloudBtn');
    if (syncCloudBtn) {
      syncCloudBtn.addEventListener('click', async () => {
        const cfg = getRuntimeConfig();
        if (!isUserAuthorizedAdmin(currentUser, cfg)) {
          showAdminAlert('拒絕存取：請先通過 Firebase Auth 驗證且確認 UID 已列入白名單！', true);
          return;
        }
        if (!window.TCStorefrontGallery) return;
        const currentList = window.TCStorefrontGallery.getPhotos();
        syncCloudBtn.disabled = true;
        syncCloudBtn.textContent = '☁️ 同步中...';
        try {
          const res = await syncEntireGalleryListToFirestore(currentList);
          if (res.synced) {
            try {
              localStorage.setItem('tcstorefront_gallery_cache', JSON.stringify(res.normalizedList));
            } catch (e) {}
            window.TCStorefrontGallery.updatePhotos(res.normalizedList);
            renderAdminPhotoList();
            showAdminAlert(`✓ 已成功將目前前台展示照片清單（共 ${res.count} 張）完整同步發布至 Firebase 雲端！`, false);
          }
        } catch (err) {
          showAdminAlert(`雲端同步失敗：${err.message}`, true);
        } finally {
          syncCloudBtn.disabled = false;
          syncCloudBtn.textContent = '☁️ 同步發布目前清單至雲端';
        }
      });
    }

    const cancelDelBtn = document.getElementById('cancelDeletePhotoBtn');
    const confirmDelBtn = document.getElementById('confirmDeletePhotoBtn');
    if (cancelDelBtn) cancelDelBtn.addEventListener('click', closeDeleteConfirmModal);
    if (confirmDelBtn) confirmDelBtn.addEventListener('click', executeConfirmedDeletion);

    const resetBtn = document.getElementById('resetDefaultPhotosBtn');
    if (resetBtn) {
      resetBtn.addEventListener('click', async () => {
        const cfg = getRuntimeConfig();
        if (!isUserAuthorizedAdmin(currentUser, cfg)) {
          showAdminAlert('拒絕存取：請先通過 Firebase Auth 驗證且確認 UID 已列入白名單！', true);
          return;
        }
        if (!window.TCStorefrontGallery) return;
        const defaults = window.TCStorefrontGallery.getDefaultPhotos().map((p, i) => ({
          ...p,
          order: i + 1
        }));
        try {
          localStorage.removeItem('tcstorefront_gallery_cache');
        } catch (e) {}
        window.TCStorefrontGallery.updatePhotos(defaults);
        renderAdminPhotoList();

        try {
          const syncRes = await syncEntireGalleryListToFirestore(defaults);
          if (syncRes.synced) {
            showAdminAlert('✓ 已還原為預設 7 張店面實景照片並同步更新至 Firebase 雲端。', false);
          } else {
            showAdminAlert('✓ 已還原為預設 7 張店面實景照片。', false);
          }
        } catch (err) {
          showAdminAlert(`已還原本機預設 7 張照片，但雲端同步失敗：${err.message}`, true);
        }
      });
    }
  }

  window.TCStorefrontAdmin = {
    openModal: async () => {
      buildAdminModalDom();
      const modal = document.getElementById('stealthAdminModal');
      if (modal) modal.classList.remove('hidden');
      await ensureFirebaseInitialized();
      renderAdminState();
    }
  };
})();
