/* =====================================================
   Service Worker — 유재진 100세 캐시플로우 PWA
   ===================================================== */
const CACHE = 'jjcf-v1';
const CORE = [
  '/100se-cashflow/',
  '/100se-cashflow/index.html',
  '/100se-cashflow/manifest.json',
  '/100se-cashflow/icon-192.png',
  '/100se-cashflow/icon-512.png',
  'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js'
];

/* 설치: 핵심 파일 캐시 */
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(CORE)).then(() => self.skipWaiting())
  );
});

/* 활성화: 구 캐시 삭제 */
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

/* fetch: Cache-First (오프라인 지원) */
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request).then(res => {
        if (!res || res.status !== 200 || res.type === 'opaque') return res;
        const clone = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, clone));
        return res;
      }).catch(() => caches.match('/100se-cashflow/'));
    })
  );
});

/* BroadcastChannel — 탭 간 실시간 동기화 */
self.addEventListener('message', e => {
  if (e.data && e.data.type === 'SYNC') {
    self.clients.matchAll().then(clients => {
      clients.forEach(c => { if (c !== e.source) c.postMessage(e.data); });
    });
  }
});
