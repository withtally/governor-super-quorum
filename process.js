const fs = require('fs');

// Function to remove block comments
function removeBlockComments(content) {
    const blockCommentRegex = /\/\*\*[\s\S]*?\*\//gm;
    return content.replace(blockCommentRegex, '');
}

// Function to split content into parts
function splitContent(content, numberOfParts) {
    const partLength = Math.ceil(content.length / numberOfParts);
    let parts = [];
    for (let i = 0; i < numberOfParts; i++) {
        parts.push(content.slice(i * partLength, (i + 1) * partLength));
    }
    return parts;
}

// Function to process and split a file
function processAndSplitFile(filePath, numberOfParts) {
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            console.error(`Error reading file: ${err}`);
            return;
        }

        // Remove comments
        const result = removeBlockComments(data);

        // Split content into parts
        const parts = splitContent(result, numberOfParts);

        // Write each part to a separate file
        parts.forEach((part, index) => {
            fs.writeFile(`${filePath}.part${index + 1}.sol`, part, 'utf8', err => {
                if (err) {
                    console.error(`Error writing part ${index + 1}: ${err}`);
                } else {
                    console.log(`Part ${index + 1} saved as ${filePath}.part${index + 1}.sol`);
                }
            });
        });
    });
}

// Replace 'path/to/your/file.sol' with the path to your Solidity file
processAndSplitFile('flatten.sol', 4);
