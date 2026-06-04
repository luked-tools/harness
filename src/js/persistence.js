/**
 * IndexedDB-backed report persistence for the static browser app.
 */
(function registerPersistence(global) {
  "use strict";

  function openPersistDb(config) {
    if (!global.indexedDB) return Promise.reject(new Error("IndexedDB unavailable"));
    return new Promise((resolve, reject) => {
      const request = global.indexedDB.open(config.dbName, config.version);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(config.storeName)) db.createObjectStore(config.storeName);
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async function loadPersistedReport(config) {
    try {
      const db = await openPersistDb(config);
      return await new Promise((resolve, reject) => {
        const tx = db.transaction(config.storeName, "readonly");
        const request = tx.objectStore(config.storeName).get(config.key);
        request.onsuccess = () => resolve(request.result?.version === config.version ? request.result.report : null);
        request.onerror = () => reject(request.error);
        tx.oncomplete = () => db.close();
        tx.onerror = () => {
          db.close();
          reject(tx.error);
        };
      });
    } catch {
      return null;
    }
  }

  async function persistReport(report, config, options = {}) {
    const warn = options.warn || (() => {});
    try {
      const db = await openPersistDb(config);
      await new Promise((resolve, reject) => {
        const tx = db.transaction(config.storeName, "readwrite");
        tx.objectStore(config.storeName).put({ version: config.version, savedAt: Date.now(), report }, config.key);
        tx.oncomplete = () => {
          db.close();
          resolve();
        };
        tx.onerror = () => {
          db.close();
          reject(tx.error);
        };
      });
    } catch (error) {
      warn("Harness could not retain the loaded pcap report.", error);
    }
  }

  async function clearPersistedReport(config, options = {}) {
    const warn = options.warn || (() => {});
    try {
      const db = await openPersistDb(config);
      await new Promise((resolve, reject) => {
        const tx = db.transaction(config.storeName, "readwrite");
        tx.objectStore(config.storeName).delete(config.key);
        tx.oncomplete = () => {
          db.close();
          resolve();
        };
        tx.onerror = () => {
          db.close();
          reject(tx.error);
        };
      });
    } catch (error) {
      warn("Harness could not clear the retained pcap report.", error);
    }
  }

  global.HarnessPersistence = Object.freeze({
    openPersistDb,
    loadPersistedReport,
    persistReport,
    clearPersistedReport
  });
})(window);
