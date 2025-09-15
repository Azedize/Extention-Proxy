// ===========================
// 🔑 Constantes principales
// ===========================
const COMBINED_KEYS = `&log`; // المفاتيح المدمجة
const PBKDF2_ITERATIONS = 100000;
const SALT_LEN = 16;
const IV_LEN = 12;
const KEY_LEN = 256; // bits

const processingTabs = {}; // لتجنب المعالجة المتكررة لنفس التاب

// ===========================
// 🔄 Fonctions utilitaires
// ===========================

// تحويل HEX → Uint8Array
function hexToBytes(hex) {
    console.log("🔹 hexToBytes reçu :", hex);
    if (hex.length % 2 !== 0) console.warn("⚠️ Longueur hex impaire :", hex.length);
    const bytes = new Uint8Array(Math.floor(hex.length / 2));
    for (let i = 0; i < bytes.length * 2; i += 2) {
        const byte = parseInt(hex.substr(i, 2), 16);
        if (isNaN(byte)) throw new Error("💥 Caractère hex invalide :" + hex.substr(i, 2));
        bytes[i / 2] = byte;
    }
    return bytes;
}

// Uint8Array → String
function bytesToString(bytes) {
    return new TextDecoder().decode(bytes);
}

// توليد المفتاح من كلمة مرور و salt
async function deriveKey(password, saltBytes) {
    const pwKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    const key = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            hash: "SHA-256",
            salt: saltBytes,
            iterations: PBKDF2_ITERATIONS
        },
        pwKey,
        { name: "AES-GCM", length: KEY_LEN },
        false,
        ["decrypt", "encrypt"]
    );
    return key;
}

// فك تشفير AES-GCM
async function decryptAESGCM(password, hexPayload) {
    const payload = hexToBytes(hexPayload);
    const salt = payload.slice(0, SALT_LEN);
    const iv = payload.slice(SALT_LEN, SALT_LEN + IV_LEN);
    const data = payload.slice(SALT_LEN + IV_LEN); // ciphertext + tag

    const key = await deriveKey(password, salt);
    const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
    return bytesToString(new Uint8Array(plainBuf));
}

// إرسال الرسائل للـ content script
function sendMessageToContentScript(tabId, message, onSuccess, onError) {
    chrome.tabs.sendMessage(tabId, message, (response) => {
        if (chrome.runtime.lastError) {
            if (onError) onError(chrome.runtime.lastError);
        } else {
            if (onSuccess) onSuccess(response);
        }
    });
}











// ===========================
// 🔍 Extraction des données depuis URL
// ===========================
async function extractProxyFromUrl(url, tabId, sendNow = true) {
    try {
        console.log("🔹 Début extractProxyFromUrl pour tabId:", tabId, "URL brute:", url);

        if (!url.startsWith("https://")) {
            console.log("⚠️ URL ne commence pas par https://, arrêt.");
            return null;
        }

        const decodedUrl = decodeURIComponent(url);
        console.log("🔹 URL après decodeURIComponent:", decodedUrl);

        let clean = decodedUrl.replace("https://", "").replace(".com", "").replace(/\//g, "");
        console.log("🧹 URL nettoyée:", clean);

        const keys = clean.match(/&[A-Za-z0-9]+/g) || [];
        console.log("🔑 Clés détectées:", keys);

        if (!keys.includes("&log")) {
            console.log("❌ Clé &Log non trouvée dans URL, arrêt du traitement");
            return null;
        }

        let hexPayload = clean;
        keys.forEach(k => { hexPayload = hexPayload.replace(k, ""); });
        console.log("🔐 Données chiffrées après retrait des clés:", hexPayload);

        const decrypted = await decryptAESGCM(
            "A9!fP3z$wQ8@rX7kM2#dN6^bH1&yL4t*",
            hexPayload
        );
        console.log("✅ Données déchiffrées:", decrypted);

        const parts = decrypted.split(";");
        console.log("🔹 Parts après split(';'):", parts);
        if (parts.length < 5) return null;

        const extraParts = parts.slice(4);
        if (extraParts.length === 0) return null;

        let dataToSend = {};
        if (extraParts.length === 1) dataToSend = { profile_email: extraParts[0] };
        else if (extraParts.length === 2) dataToSend = { profile_email: extraParts[0], profile_password: extraParts[1] };
        else dataToSend = { profile_email: extraParts[0], profile_password: extraParts[1], recovery_email: extraParts[2] };

        console.log("📤 Données préparées pour content script:", dataToSend);
        // enregistre data vers localStorage


        // ✅ Enregistrer les données dans chrome.storage.local
        await chrome.storage.local.set({ "currentData": dataToSend });
        console.log("💾 Données enregistrées:", dataToSend);

        return dataToSend;


    } catch (err) {
        console.error("💥 Erreur extractProxyFromUrl:", err);
        delete processingTabs[tabId];
        return null;
    }
}











// ===========================
// 🔔 مراقبة إنشاء تاب جديد + إغلاق القديم
// ===========================

chrome.tabs.onCreated.addListener(async (tab) => {

    const url = tab.pendingUrl || tab.url;

    // إذا كان هناك تاب قيد المعالجة بالفعل، تجاهله
    if (processingTabs[tab.id]) return;

    processingTabs[tab.id] = true;
    console.log("🚀 Nouvel onglet détecté pour traitement:", tab.id);

    // استخراج البيانات بدون إرسال
    const dataToSend = await extractProxyFromUrl(url, tab.id, false);
    if (!dataToSend) {
        delete processingTabs[tab.id];
        return;
    }

    console.log("✅ URL valide détectée, إيقاف مراقبة التابات الأخرى مؤقتاً");

    // إيقاف أي مراقبة مستقبلية للتابات الأخرى
    chrome.tabs.onCreated.hasListener && chrome.tabs.onCreated.removeListener();
    await sleep(4000);

    // فتح تاب جديد على Google Accounts
    chrome.tabs.create({ url: "https://accounts.google.com/" }, (newTab) => {
        console.log("📂 Nouveau tab créé:", newTab.id);

        // إغلاق جميع التابات القديمة باستثناء التاب الجديد
        chrome.tabs.query({}, (tabs) => {
            tabs.forEach(t => {
                if (t.id !== newTab.id) {
                    chrome.tabs.remove(t.id, () => {
                        console.log("🗑️ Tab fermé:", t.id);
                    });
                }
            });
        });

        // انتظار تحميل التاب الجديد ثم إرسال البيانات
        chrome.tabs.onUpdated.addListener(function listener(tabId, changeInfo) {
            if (tabId === newTab.id && changeInfo.status === "complete") {
                chrome.tabs.onUpdated.removeListener(listener);
                console.log("✅ Tab nouveau complètement chargé:", newTab.id);

                sendMessageToContentScript(newTab.id, { action: "startProcess", ...dataToSend },
                    () => {
                        console.log("📩 Données envoyées au content script:", newTab.id);
                        delete processingTabs[newTab.id];
                    },
                    (err) => {
                        console.error("❌ Erreur en envoyant les données:", newTab.id, err);
                        delete processingTabs[newTab.id];
                    }
                );
            }
        });
    });
});











chrome.webNavigation.onCompleted.addListener(async (details) => {

    console.log("➡️ Navigation completed pour tabId:",  details.tabId, "URL:", details.url);

    const ignoredUrls = [
        "https://contacts.google.com",
        "https://www.google.com/maps",
        "https://trends.google.com/trends/"
    ];

    const monitoredPatterns = [
        "https://mail.google.com/mail",
        "https://workspace.google.com/",
        "https://accounts.google.com/",
        "https://accounts.google.com/signin/v2/",
        "https://myaccount.google.com/security",
        "https://gds.google.com/",
        "https://myaccount.google.com/interstitials/birthday",
        "https://gds.google.com/web/recoveryoptions",
        "https://gds.google.com/web/homeaddress"
    ];

    if (ignoredUrls.some(prefix => details.url.startsWith(prefix))) {
        console.log("🚫 URL ignored (startsWith match):", details.url);
        return;
    }

    // استرجاع البيانات من localStorage باستخدام المفتاح الثابت
    const storedDataJson = await chrome.storage.local.get("currentData");
    const dataToSend = storedDataJson["currentData"];

    if (!dataToSend) {
        console.warn("⚠️ Pas de données stockées, contenu actuel du storage:", storedDataJson);
        return;
    }

    // التأكد من أن URL مراقب
    let shouldProcess = false;
    for (const part of monitoredPatterns) {
        console.log(`🔹 Vérification pattern: "${part}" avec URL: "${details.url}"`);
        if (details.url.includes(part) || details.url.startsWith(part)) {
            console.log(`✅ URL matched pour le pattern: "${part}"`);
            shouldProcess = true;
            break;
        }
    }
    if (details.url === "chrome://newtab/") {
        shouldProcess = true;
        console.log("✅ URL is a new tab");
    }

    if (!shouldProcess) {
        console.log("⚠️ URL did not match any monitored pattern:", details.url);
        return;
    }

    // Avoid processing same tab twice
    if (processingTabs[details.tabId]) {
        console.log("⚠️ Tab already being processed, skipping:", details.tabId);
        return;
    }

    processingTabs[details.tabId] = true;

    sendMessageToContentScript(
        details.tabId,
        { action: "startProcess", ...dataToSend },
        (response) => {
            console.log("📩 Process response received for tab:", details.tabId, "Response:", response);
            delete processingTabs[details.tabId];
        },
        (error) => {
            console.error("❌ Error during processing tab:", details.tabId, "Error:", error);
            delete processingTabs[details.tabId];
        }
    );

    // Async sleep example
    await new Promise(resolve => setTimeout(resolve, 5000));
});









async function sleep(ms) {
    const totalSeconds = Math.ceil(ms / 1000);
    for (let i = 1; i <= totalSeconds; i++) {
        console.log(`⏳ Attente... ${i} seconde(s) écoulée(s)`);
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
    console.log("✅ Pause terminée !");
}

