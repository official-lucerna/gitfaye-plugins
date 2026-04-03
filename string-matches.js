"use strict";

// Variables
const stringMatches = require("./database/string-matches.json")

// Main
module.exports = (data) => {
    // Validations
    if (!data || typeof data !== "string") return []
    
    // Variables
    const detections = []
    
    // Core
    for ( const item of stringMatches ) {
        try {
            const regex = new RegExp(item.match, "g")

            if (regex.test(data)) detections.push({
                name: item.name,
                risk: item.risk,
                severity: item.severity
            })
        }catch{}
    }
    
    return detections
}