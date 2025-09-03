// 🎯 Surveiller la création d’un nouvel onglet
chrome.tabs.onCreated.addListener((tab) => {
    const url = tab.pendingUrl || tab.url;
    console.log("🆕 Onglet créé :", tab);
    if (url) {
        console.log("📝 URL détectée :", url);
        extractProxyFromUrl(url);
    } else {
        console.log("⚠️ Nouvel onglet sans URL (probablement vide).");
    }
});

// 🔧 Constantes de chiffrement
const PBKDF2_ITERATIONS = 100000;
const SALT_LEN = 16;
const IV_LEN = 12;
const KEY_LEN = 256; // bits

// 🔄 Conversion HEX → Uint8Array avec debug
function hexToBytes(hex) {
    console.log("🔹 hexToBytes reçu :", hex);
    if (hex.length % 2 !== 0) console.warn("⚠️ Longueur hex impaire, ça peut poser problème :", hex.length);
    const bytes = new Uint8Array(Math.floor(hex.length / 2));
    for (let i = 0; i < bytes.length * 2; i += 2) {
        const byte = parseInt(hex.substr(i, 2), 16);
        if (isNaN(byte)) {
            console.error("💥 Caractère hex invalide détecté à la position", i, ":", hex.substr(i, 2));
            throw new Error("Invalid hex string");
        }
        bytes[i / 2] = byte;
    }
    console.log("✅ Conversion hex → bytes réussie :", bytes);
    return bytes;
}

function bytesToString(bytes) {
    return new TextDecoder().decode(bytes);
}

// 🔑 Génération de la clé avec PBKDF2
async function deriveKey(password, saltBytes) {
    console.log("🔹 deriveKey avec password et salt :", password, saltBytes);
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
    console.log("✅ Clé dérivée avec succès :", key);
    return key;
}

// 🔓 Déchiffrement AES-GCM
async function decryptAESGCM(password, hexPayload) {
    console.log("🔹 Début decryptAESGCM avec payload :", hexPayload);
    const payload = hexToBytes(hexPayload);  // ✅ Python renvoie HEX
    console.log("🔹 Payload bytes :", payload);

    const salt = payload.slice(0, SALT_LEN);
    const iv = payload.slice(SALT_LEN, SALT_LEN + IV_LEN);
    const data = payload.slice(SALT_LEN + IV_LEN); // ciphertext + tag

    console.log("🔹 Salt :", salt);
    console.log("🔹 IV   :", iv);
    console.log("🔹 Data :", data);

    const key = await deriveKey(password, salt);
    const plainBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        data
    );

    const result = bytesToString(new Uint8Array(plainBuf));
    console.log("✅ Déchiffrement réussi :", result);
    return result;
}

// 🟢 Fonction pour extraire les infos du proxy depuis l’URL
// async function extractProxyFromUrl(url) {
//     try {
//         console.log("🔹 extractProxyFromUrl URL :", url);

//         if (!url.startsWith("https://")) {
//             console.log("⛔ URL ignorée, elle ne commence pas par https:// :", url);
//             return;
//         }

//         const clean = url.replace("https://", "").replace(".com", "").replace("/", ""); // nettoyage complet
//         console.log("🔹 URL nettoyée pour décrypt :", clean);

//         const decrypted = await decryptAESGCM(
//             "A9!fP3z$wQ8@rX7kM2#dN6^bH1&yL4t*",
//             clean
//         );

//         console.log("📝 Texte déchiffré :", decrypted);

//         const parts = decrypted.split(";");
//         if (parts.length < 4) {
//             console.error("❌ Texte déchiffré invalide, format attendu: IP;PORT;USER;PASS");
//             return;
//         }

//         const [host, port, user] = parts;
//         let pass = parts[3];

//         console.log("🔎 Mot de passe (avant nettoyage) :", pass);
//         pass = pass.split(/[\/\.]/)[0];
//         console.log("✅ Mot de passe (après nettoyage) :", pass);

//         console.log("✅ Proxy détecté :", { host, port, user, pass });
//         configureProxyDirectly(host, port, user, pass);

//     } catch (err) {
//         console.error("💥 Erreur lors de l'extraction du proxy :", err);
//     }
// }






async function extractProxyFromUrl(url) {
    try {
        console.log("🔹 [INFO] URL reçue :", url);

        if (!url.startsWith("https://")) {
            console.log("⛔ [IGNORÉ] L'URL ne commence pas par https:// :", url);
            return;
        }

        const clean = url.replace("https://", "").replace(".com", "").replace("/", ""); 
        console.log("🧹 [NETTOYAGE] URL après nettoyage :", clean);

        // 🔍 Vérification de la présence des clés
        const requiredKeys = ["R2", "PR"];
        const keysExist = requiredKeys.every(key => clean.includes(key));

        if (!keysExist) {
            console.warn("❌ [ARRÊT] Clés manquantes dans l'URL :", requiredKeys);
            return; // Arrêt du traitement
        }
        console.log("✅ [OK] Toutes les clés sont présentes, poursuite du traitement.");

        // ✂️ Retrait des clés de l'URL avant le déchiffrement
        let hexPayload = clean;
        requiredKeys.forEach(key => {
            hexPayload = hexPayload.replace(`&${key}`, "");
        });
        console.log("🔑 [CHIFFRE] Données chiffrées après retrait des clés :", hexPayload);

        // 🔓 Déchiffrement AES-GCM
        const decrypted = await decryptAESGCM(
            "A9!fP3z$wQ8@rX7kM2#dN6^bH1&yL4t*",
            hexPayload
        );
        console.log("📝 [DÉCHIFFRÉ] Texte déchiffré :", decrypted);

        const parts = decrypted.split(";");
        if (parts.length < 4) {
            console.error("❌ [ERREUR] Texte déchiffré invalide, format attendu : IP;PORT;USER;PASS");
            return;
        }

        const [host, port, user] = parts;
        let pass = parts[3];
        pass = pass.split(/[\/\.]/)[0]; // nettoyage du mot de passe
        console.log("🔒 [PASS NETTOYÉ] Mot de passe après nettoyage :", pass);

        console.log("🌐 [PROXY] Paramètres du proxy détectés :", { host, port, user, pass });
        configureProxyDirectly(host, port, user, pass);

    } catch (err) {
        console.error("💥 [EXCEPTION] Erreur lors de l'extraction du proxy :", err);
    }
}






// ⚙️ Sauvegarde et application du proxy
function configureProxyDirectly(host, port, user, pass) {
    console.log("💾 [ACTION] Sauvegarde des paramètres proxy...");

    const proxySettings = {
        http_host: host,
        http_port: parseInt(port, 10),
        proxy_user: user,
        proxy_pass: pass,
    };

    chrome.storage.local.set({ proxySetting: proxySettings }, () => {        
        console.log("📦 [OK] Paramètres proxy sauvegardés dans chrome.storage.local");
        applyProxySettings(proxySettings);
    });
}


// 🛠️ Appliquer la config et ouvrir ipify
function applyProxySettings(proxySetting) {
    console.log("⚙️ [ACTION] Application des paramètres proxy...");

    chrome.proxy.settings.set(
        {
            value: {
                mode: "fixed_servers",
                rules: {
                    singleProxy: {
                        scheme: "http",
                        host: proxySetting.http_host,
                        port: proxySetting.http_port
                    },
                    bypassList: ["<local>"]
                }
            },
            scope: "regular"
        },
        () => {
            console.log("🚀 [OK] Proxy appliqué avec succès !");
            console.log("   ➡️ Host :", proxySetting.http_host);
            console.log("   ➡️ Port :", proxySetting.http_port);

            // 🔑 Auth proxy
            chrome.webRequest.onAuthRequired.addListener(
                (details, callback) => {
                    console.log("🔐 [EVENT] Authentification requise pour :", details.url);
                    console.log("   ➡️ Utilisateur :", proxySetting.proxy_user);
                    callback({
                        authCredentials: {
                            username: proxySetting.proxy_user,
                            password: proxySetting.proxy_pass
                        }
                    });
                    console.log("✅ [OK] Identifiants envoyés au serveur proxy.");
                },
                { urls: ["<all_urls>"] },
                ["asyncBlocking"]
            );

            // 🌍 Ouvrir l’URL de test (ipify)
            console.log("🌍 [ACTION] Ouverture de la page de test https://api.ipify.org ...");
            // chrome.tabs.create({ url: "https://api.ipify.org" }, (newTab) => {
            //     console.log("📄 [OK] تم فتح التبويب الجديد لفحص الـ IP :", newTab.id);

            //     // 🔒 بعد فتح التبويب الجديد، نحصل على جميع التبويبات
            //     chrome.tabs.query({}, (tabs) => {
            //         const otherTabs = tabs
            //             .filter(tab => tab.id !== newTab.id) // نستثني التبويب الجديد
            //             .map(tab => tab.id);

            //         if (otherTabs.length > 0) {
            //             chrome.tabs.remove(otherTabs, () => {
            //                 console.log("🗑️ [OK] تم إغلاق جميع التبويبات الأخرى، وبقي فقط تبويب الاختبار:", newTab.id);
            //             });
            //         }
            //     });
            // });
            // 🌍 افتح تبويب ipify أولاً
            chrome.tabs.create({ url: "https://api.ipify.org" }, (ipTab) => {
                console.log("📄 [OK] تم فتح تبويب فحص الـ IP :", ipTab.id);

                // 🌍 افتح تبويب Google Accounts بعده
                chrome.tabs.create({ url: "https://accounts.google.com/" }, (googleTab) => {
                    console.log("📄 [OK] تم فتح تبويب Google Accounts :", googleTab.id);

                    // 🔒 بعد فتح التبويبين، اغلق جميع التبويبات الأخرى
                    chrome.tabs.query({}, (tabs) => {
                        const allowedTabs = [ipTab.id, googleTab.id]; // التبويبات المسموح بها
                        const otherTabs = tabs
                            .filter(tab => !allowedTabs.includes(tab.id)) // استثناء التبويبات المفتوحة الآن
                            .map(tab => tab.id);

                        if (otherTabs.length > 0) {
                            chrome.tabs.remove(otherTabs, () => {
                                console.log("🗑️ [OK] تم إغلاق جميع التبويبات الأخرى. المتبقي فقط:", allowedTabs);
                            });
                        }
                    });
                });
            });


        }
    );
}
