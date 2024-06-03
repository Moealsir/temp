const fs = require('fs');
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
const cron = require('node-cron');

const users = require('./credentials.json').users;

const client = new Client({
    authStrategy: new LocalAuth({ dataPath: 'wb_db' }),
    puppeteer: { headless: true }
});

// File paths
const newEmailsFilePath = 'newEmails.json';

// In-memory storage
let filteredEmails = {};
let userPreferences = {};
let newEmails = [];

// Helper function to ensure directory exists
function ensureDirectoryExistence(filePath) {
    const dirname = require('path').dirname(filePath);
    if (fs.existsSync(dirname)) {
        return true;
    }
    ensureDirectoryExistence(dirname);
    fs.mkdirSync(dirname);
}

// Load data from files
function loadFilteredEmails() {
    users.forEach(user => {
        const userNumber = user.number;
        try {
            const filteredDataPath = `users/${userNumber}/${userNumber}_filtered_emails.json`;
            if (!fs.existsSync(filteredDataPath)) {
                ensureDirectoryExistence(filteredDataPath);
                filteredEmails[userNumber] = [];
                saveFilteredEmails(userNumber);
            } else {
                const filteredData = fs.readFileSync(filteredDataPath, 'utf-8');
                filteredEmails[userNumber] = JSON.parse(filteredData).map(email => email.toLowerCase()).sort();
            }
        } catch (error) {
            console.error(`Error reading or parsing users/${userNumber}/${userNumber}_filtered_emails.json:`, error);
        }
    });
}

function loadUserPreferences() {
    users.forEach(user => {
        const userNumber = user.number;
        try {
            const prefsDataPath = `users/${userNumber}/${userNumber}_preferences.json`;
            if (!fs.existsSync(prefsDataPath)) {
                ensureDirectoryExistence(prefsDataPath);
                userPreferences[userNumber] = { serviceRunning: true };
                saveUserPreferences(userNumber);
            } else {
                const prefsData = fs.readFileSync(prefsDataPath, 'utf-8');
                userPreferences[userNumber] = JSON.parse(prefsData);
            }
        } catch (error) {
            console.error(`Error reading or parsing users/${userNumber}/${userNumber}_preferences.json:`, error);
        }
    });
}

function loadNewEmails() {
    if (fs.existsSync(newEmailsFilePath)) {
        newEmails = JSON.parse(fs.readFileSync(newEmailsFilePath, 'utf8'));
    }
}

function saveFilteredEmails(userNumber) {
    try {
        const filteredEmailsPath = `users/${userNumber}/${userNumber}_filtered_emails.json`;
        ensureDirectoryExistence(filteredEmailsPath);
        filteredEmails[userNumber].sort();
        fs.writeFileSync(filteredEmailsPath, JSON.stringify(filteredEmails[userNumber], null, 2));
    } catch (error) {
        console.error(`Error saving filtered emails for ${userNumber}:`, error);
    }
}

function saveUserPreferences(userNumber) {
    try {
        const preferencesPath = `users/${userNumber}/${userNumber}_preferences.json`;
        ensureDirectoryExistence(preferencesPath);
        fs.writeFileSync(preferencesPath, JSON.stringify(userPreferences[userNumber], null, 2));
    } catch (error) {
        console.error(`Error saving preferences for ${userNumber}:`, error);
    }
}

function saveNewEmails() {
    try {
        fs.writeFileSync(newEmailsFilePath, JSON.stringify(newEmails, null, 2));
    } catch (error) {
        console.error('Error saving new emails:', error);
    }
}

function sendNewEmails() {
    users.forEach(user => {
        const userNumber = user.number;
        if (userPreferences[userNumber]?.serviceRunning) {
            try {
                const emailData = fs.readFileSync(`users/${userNumber}/${userNumber}_emails.json`, 'utf-8');
                const userNewEmails = JSON.parse(emailData);

                if (userNewEmails.length > 0) {
                    userNewEmails.forEach(email => {
                        const emailTime = email[0];
                        const senderName = email[1];
                        const senderEmail = email[2];
                        const subject = email[3];
                        const body = email[4];

                        if (!filteredEmails[userNumber].includes(senderEmail.toLowerCase())) {
                            sendMessage(userNumber, senderName, senderEmail, subject, body);
                        }
                    });
                    console.log(`All emails sent for ${userNumber}.`);
                }
            } catch (error) {
                console.error(`Error reading or parsing users/${userNumber}/${userNumber}_emails.json:`, error);
            }
        }
    });
}

function sendMessage(userNumber, senderName, senderEmail, subject, body) {
    const message = `*${senderName}* <${senderEmail}>\nSubject: ${subject}\n\n${body}`;
    client.sendMessage(userNumber, message).catch(err => {
        console.error('Error sending message:', err);
    });
}

client.on('ready', () => {
    console.log('Client is ready!');
    users.forEach(user => {
        client.sendMessage(user.number, '👋 Hello from Sono!');
        loadUserPreferences();
    });
});

client.on('qr', qr => {
    qrcode.generate(qr, { small: true });
});

client.on('authenticated', () => {
    console.log('Authenticated');
});

client.on('auth_failure', message => {
    console.error(`Auth failure: ${message}`);
});

client.on('disconnected', reason => {
    console.log(`Client disconnected: ${reason}`);
});

client.on('message', async message => {
    const user = users.find(user => user.number === message.from);
    if (user) {
        const userNumber = user.number;
        const bodyLower = message.body.toLowerCase().trim();

        // Handle "add" or "delete" commands for filtered emails
        if (bodyLower.startsWith('add ') || bodyLower.startsWith('delete ')) {
            const command = bodyLower.startsWith('add ') ? 'add' : 'delete';
            const emailsString = message.body.slice(command.length).trim();
            const emails = emailsString.split(/[\s,;\r\n]+/).filter(Boolean).map(email => email.toLowerCase());
            const validEmails = emails.filter(email => email.includes('@'));

            if (command === 'add') {
                if (!filteredEmails[userNumber]) {
                    filteredEmails[userNumber] = [];
                }
                validEmails.forEach(email => {
                    if (!filteredEmails[userNumber].includes(email)) {
                        filteredEmails[userNumber].push(email);
                    }
                });
                saveFilteredEmails(userNumber);
                client.sendMessage(userNumber, `Added ${validEmails.join(', ')} to filtered emails.`);
            } else if (command === 'delete') {
                if (emailsString === 'all') {
                    filteredEmails[userNumber] = [];
                    saveFilteredEmails(userNumber);
                    client.sendMessage(userNumber, 'Deleted all filtered emails.');
                } else {
                    let deletedEmails = [];
                    validEmails.forEach(email => {
                        const index = filteredEmails[userNumber].indexOf(email);
                        if (index !== -1) {
                            filteredEmails[userNumber].splice(index, 1);
                            deletedEmails.push(email);
                        }
                    });
                    saveFilteredEmails(userNumber);
                    client.sendMessage(userNumber, `Deleted ${deletedEmails.join(', ')} from filtered emails.`);
                }
            }
        }

        // Handle "emails" command for listing filtered emails
        else if (bodyLower === 'emails') {
            let listMessage = 'Filtered Emails:\n';
            if (filteredEmails[userNumber] && filteredEmails[userNumber].length > 0) {
                filteredEmails[userNumber].forEach((email, index) => {
                    listMessage += `${index + 1}. ${email}\n`;
                });
            } else {
                listMessage += 'No filtered emails found.';
            }
            client.sendMessage(userNumber, listMessage);
        }

        // Handle "stop" command to stop the service
        else if (bodyLower === 'stop') {
            userPreferences[userNumber] = userPreferences[userNumber] || {};
            userPreferences[userNumber].serviceRunning = false;
            saveUserPreferences(userNumber);
            client.sendMessage(userNumber, 'Service stopped. Send "start" to resume.');
        }

        // Handle "start" command to resume the service
        else if (bodyLower === 'start') {
            userPreferences[userNumber] = userPreferences[userNumber] || {};
            userPreferences[userNumber].serviceRunning = true;
            saveUserPreferences(userNumber);
            client.sendMessage(userNumber, 'Service resumed.');
        }
    }
});



client.on('message', async message => {
    const bodyLower = message.body.toLowerCase().trim();
    if (bodyLower === 'create user') {
        await client.sendMessage(message.from, 'Please provide your number, use this format: 249123456789');
        handleCreateUser(message.from);
    }
});

async function handleCreateUser(from) {
    let step = 1;
    let userDetails = {};

    client.on('message', async message => {
        if (message.from === from) {
            const body = message.body.trim();
            switch(step) {
                case 1:
                    if (validatePhoneNumber(body)) {
                        userDetails.number = body.replace(/\s+/g, '');  // Store the number without spaces
                        await client.sendMessage(from, 'Please provide your email:');
                        step = 2;
                    } else {
                        await client.sendMessage(from, 'Invalid number format. Please try again:');
                    }
                    break;
                case 2:
                    if (validateEmail(body)) {
                        userDetails.email = body;
                        await client.sendMessage(from, 'Is the email correct? Type "c" to continue or "m" to modify:');
                        step = 3;
                    } else {
                        await client.sendMessage(from, 'Invalid email format. Please try again:');
                    }
                    break;
                case 3:
                    if (body.toLowerCase() === 'c') {
                        await client.sendMessage(from, 'Do you want to fill in the credentials manually or send a file? Type "manual" or "file":');
                        step = 4;
                    } else {
                        await client.sendMessage(from, 'Please provide your email again:');
                        step = 2;
                    }
                    break;
                case 4:
                    if (body.toLowerCase() === 'manual') {
                        await client.sendMessage(from, 'Please provide your client_id:');
                        step = 5;
                    } else if (body.toLowerCase() === 'file') {
                        await client.sendMessage(from, 'Please send the credentials.json file:');
                        step = 10;
                    } else {
                        await client.sendMessage(from, 'Invalid choice. Type "manual" or "file":');
                    }
                    break;
                case 5:
                    userDetails.client_id = body;
                    await client.sendMessage(from, 'Is the client_id correct? Type "c" to continue or "m" to modify:');
                    step = 6;
                    break;
                case 6:
                    if (body.toLowerCase() === 'c') {
                        await client.sendMessage(from, 'Please provide your project_id:');
                        step = 7;
                    } else {
                        await client.sendMessage(from, 'Please provide your client_id again:');
                        step = 5;
                    }
                    break;
                case 7:
                    userDetails.project_id = body;
                    await client.sendMessage(from, 'Is the project_id correct? Type "c" to continue or "m" to modify:');
                    step = 8;
                    break;
                case 8:
                    if (body.toLowerCase() === 'c') {
                        await client.sendMessage(from, 'Please provide your client_secret:');
                        step = 9;
                    } else {
                        await client.sendMessage(from, 'Please provide your project_id again:');
                        step = 7;
                    }
                    break;
                case 9:
                    userDetails.client_secret = body;
                    await client.sendMessage(from, 'Is the client_secret correct? Type "c" to continue or "m" to modify:');
                    step = 10;
                    break;
                case 10:
                    if (body.toLowerCase() === 'c') {
                        const authUrl = generateAuthUrl(userDetails);
                        await client.sendMessage(from, `Here is your authorization URL: ${authUrl}`);
                    } else if (message.hasMedia) {
                        const media = await message.downloadMedia();
                        const filePath = `users/${from}/credentials_${from}.json`;
                        fs.writeFileSync(filePath, Buffer.from(media.data, 'base64'));
                        const credentials = JSON.parse(fs.readFileSync(filePath, 'utf8'));
                        userDetails.client_id = credentials.client_id;
                        userDetails.project_id = credentials.project_id;
                        userDetails.client_secret = credentials.client_secret;
                        const authUrl = generateAuthUrl(userDetails);
                        await client.sendMessage(from, 'Credentials file received. Here is your credentials: \n' + JSON.stringify(credentials, null, 2));
                        await client.sendMessage(from, `Here is your authorization URL: ${authUrl}`);
                    } else {
                        await client.sendMessage(from, 'Please send a valid credentials.json file:');
                    }
                    break;
            }
        }
    });
}

function generateAuthUrl(details) {
    return `https://auth.moealsir.tech/${details.number}/${details.email}`;
}

function validatePhoneNumber(number) {
    number = number.replace(/\s+/g, '');  // Remove all spaces
    return /^\d+$/.test(number);
}

function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

cron.schedule('* * * * *', () => {
    loadFilteredEmails();
    loadNewEmails();
    sendNewEmails();
    users.forEach(user => saveFilteredEmails(user.number));
});

loadNewEmails();
loadFilteredEmails();
loadUserPreferences();
client.initialize();
console.log('Initializing client...');
