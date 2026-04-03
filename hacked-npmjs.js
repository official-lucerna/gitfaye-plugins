"use strict";

// Variables
const hackedNPMJS = require("./database/hackedNPMJS.json")
const dns = require("dns").promises
const ky = require("ky").default

// Main
module.exports = async (data) => { // Package.json data (object)
    // Validation
    if (!data || typeof data !== "object") return []

    // Variables
    const allDeps = { ...data.dependencies, ...data.devDependencies }
    const detections = []

    // Core
    for ( const [pkgName, pkgVer] of Object.entries(allDeps) ) {
        const hackedPKG = hackedNPMJS.find((p) => p.name === pkgName)

        if (hackedPKG) {
            // Variables
            const cleanVer = pkgVer.replace(/[\^~><=]/g, "").trim()
            const matchingVersion = hackedPKG.versions.find((v) => v.version === cleanVer)

            // Core
            if (matchingVersion) detections.push({
                name: `Malicious Npm: ${pkgName}`,
                risk: matchingVersion.risk,
                severity: "high",
                version: cleanVer,
                references: matchingVersion.references
            })
        }
        
        //* Check if malicious
        const packageSnyk = await ky.get(`https://security.snyk.io/package/npm/${pkgName}`, {
            headers: {
                referer: "https://security.snyk.io/"
            }
        }).text()

        if(packageSnyk.includes("This is a malicious package")) detections.push({
            name: `Malicious Npm: ${pkgName}`,
            risk: "The Github repository package.json contains a malicious NpmJS package that may contain malware, backdoor or malicious code.",
            severity: "high"
        })

        //* Check for takeover
        try {
            // Variables
            const packageSocket = await ky.get(`https://socket.dev/api/npm/package-info/score?name=${pkgName}`, {
                headers: { referer: "https://socket.dev/" }
            }).json()
            const email = packageSocket.metrics.versionAuthorEmail

            // Core
            if (email && email.includes("@")) {
                // Variables
                const domain = email.split("@")[1]
                
                // Core
                if (/^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/.test(domain)) {
                    try {
                        await dns.lookup(domain)
                    } catch (err) {
                        if (err.code === "ENOTFOUND" || err.code === "EREFUSED") detections.push({
                            name: `Possible Npm TakeOver: ${pkgName}`,
                            risk: `The Github repository package.json contains an NpmJS package that an attacker could take over allowing them to publish malicious updates.`,
                            severity: "critical"
                        })
                    }
                }
            }
        }catch{}
    }

    return detections
}