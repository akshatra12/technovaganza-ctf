/*
🔍 JavaScript Reverse Engineering Challenge

This code validates a secret key. Can you find the correct key?

Analyze the validation logic to understand what input is expected.
The key follows a specific transformation pattern.
*/

function validateKey(input) {
    if (typeof input !== 'string' || input.length !== 24) {
        return false;
    }
    
    let transformed = [];
    for (let i = 0; i < input.length; i++) {
        // Complex transformation
        let val = input.charCodeAt(i);
        val = (val + i * 3) % 256;
        val = val ^ 0x55;
        val = (val + 7) % 256;
        transformed.push(val);
    }
    
    const expected = [182, 167, 184, 192, 178, 170, 193, 192, 204, 174, 191, 200, 183, 178, 200, 192, 204, 201, 183, 192, 185, 206, 204, 216];
    
    for (let i = 0; i < transformed.length; i++) {
        if (transformed[i] !== expected[i]) {
            return false;
        }
    }
    
    // Success - calculate flag
    const flagBase = btoa(input).slice(0, 12);
    console.log("✅ Valid key! Flag: Technovaganzactf{" + flagBase + "}");
    return true;
}

// Test function
function testKey() {
    const testKeys = ["test", "abcdefghijklmnopqrstuvwx", "123456789012345678901234"];
    testKeys.forEach(key => {
        console.log(`Testing: ${key}`);
        validateKey(key);
    });
}

console.log("JavaScript Reverse Engineering Challenge loaded!");
console.log("Find the correct 24-character key!");