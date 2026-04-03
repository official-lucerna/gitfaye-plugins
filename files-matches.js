"use strict";

// Variables
const filesMatches = require("./database/files-matches.json")

// Main
module.exports = (filesTree) => {
    // Validations
    if (!Array.isArray(filesTree)) return []
    
    // Variables
    const paths = filesTree.map((item) => typeof item === "string" ? item : item.path)
    const detections = []
    
    // Core
    for ( const rule of filesMatches ) {
        for ( const targetFile of rule.files ) {
            // Variables
            const isWildcard = targetFile.includes("*")
            const regex = isWildcard ? new RegExp("^" + targetFile.replace(/\*/g, ".*") + "$", "i") : null

            // Core
            const matchedPaths = paths.filter((p) => {
                // Variables
                const fileName = p.split("/").pop()

                // Core
                if (rule.depth === 1) {
                    const isRoot = !p.includes("/") || p.startsWith("./") && p.split("/").length === 2

                    if (!isRoot) return false
                    if (isWildcard) return regex.test(fileName)

                    return p === targetFile || p === `./${targetFile}`
                } else {
                    if (isWildcard) return regex.test(fileName)
                    return p.endsWith(targetFile) || p.includes(`/${targetFile}`)
                }
            })
            
            if (matchedPaths.length) detections.push({
                name: rule.name,
                risk: rule.risk,
                severity: rule.severity,
                matchedPaths: matchedPaths
            })
        }
    }
    
    return detections
}