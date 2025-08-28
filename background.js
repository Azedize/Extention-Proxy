
// 🎯 Surveiller la création d’un nouvel onglet
chrome.tabs.onCreated.addListener((tab) => {
    const url = tab.pendingUrl || tab.url;
    if (url) {
        console.log("🆕 Nouvel onglet détecté 👉", url);
        extractProxyFromUrl(url);
    } else {
        console.log("⚠️ Nouvel onglet sans URL (probablement vide).");
    }
});


// 🟢 Fonction pour extraire les infos du proxy depuis l’URL
function extractProxyFromUrl(url) {
    try {
        // ✅ Format attendu: https://IP;PORT;USER;PASS
        if (!url.startsWith("https://")) {
            console.log("⛔ URL ignorée, elle ne commence pas par https:// 👉", url);
            return;
        }

        const clean = url.replace("https://", "");
        const parts = clean.split(";");

        if (parts.length < 4) {
            console.error("❌ URL invalide, format incorrect. Exemple attendu: https://IP;PORT;USER;PASS");
            return;
        }

        const host = parts[0];
        const port = parts[1];
        const user = parts[2];
        let pass = parts[3];

        // 🔑 Affichage du mot de passe avant nettoyage
        console.log("🔎 Mot de passe (avant nettoyage):", pass);

        // ✨ Nettoyage du mot de passe : supprimer tout après "/" ou "."
        pass = pass.split(/[\/\.]/)[0].toUpperCase();

        // 🔑 Affichage du mot de passe après nettoyage
        console.log("✅ Mot de passe (après nettoyage):", pass);

        // 🎉 Affichage détaillé
        console.log("✅ Proxy détecté avec succès !");
        console.log("🌐 Adresse IP :", host);
        console.log("📡 Port       :", port);
        console.log("👤 Utilisateur:", user);
        console.log("🔑 Mot de passe:", pass);

        // ⚙️ Appliquer le proxy
        console.log("⚙️ Application de la configuration du proxy...");
        configureProxyDirectly(host, port, user, pass);
        console.log("🚀 Proxy appliqué avec succès 🎉");

    } catch (err) {
        console.error("💥 Erreur lors de l'extraction du proxy:", err);
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
            chrome.tabs.create({ url: "https://api.ipify.org" }, (tab) => {
                console.log("📄 [OK] Onglet créé pour vérifier l’IP :", tab.id);
            });
        }
    );
}
