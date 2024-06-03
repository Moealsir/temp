// Additional command handlers
client.on('message', async message => {
    const bodyLower = message.body.toLowerCase().trim();

    // Handle "new" command for new email instructions
    if (bodyLower === 'new') {
        client.sendMessage(message.from, 'Send the new email in format: email: email@email.com');
    }

    // Handle "ايميل" command for special instructions in Arabic
    else if (bodyLower === 'ايميل') {
        const messagesToSend = [
            'عايزك تعمل إيميل جديد كل ما تكون فاضي',
            'وترسل لي الإيميل بالصيغة',
            'email: email@email.com',
            'قدر ما تقدر لحدي ما قوقل يقول ليك كفاك ولا تزهج إنت',
            'متى ما تتذكر الموضوع ما إجباري',
            'إستخدم الباسويرد دا',
            'B7$xQw#t3K!9'
        ];

        function sendMessagesSequentially(messages, recipient, index = 0) {
            if (index >= messages.length) return;
            const currentMessage = messages[index];
            client.sendMessage(recipient, currentMessage).then(() => {
                setTimeout(() => {
                    sendMessagesSequentially(messages, recipient, index + 1);
                }, 1000);
            }).catch(error => {
                console.error('Error sending message:', error);
            });
        }

        sendMessagesSequentially(messagesToSend, message.from);
    }

    // Handle "news" command to list new emails
    else if (bodyLower === 'news') {
        let newsMessage = 'New Emails:\n';
        if (newEmails && newEmails.length > 0) {
            newEmails.forEach((email, index) => {
                newsMessage += `${index + 1}. ${email}\n`;
            });
        } else {
            newsMessage += 'No new emails found.';
        }
        client.sendMessage(message.from, newsMessage);
    }
    // Handle "new" command for new email instructions
    else if (bodyLower === 'new') {
        client.sendMessage(message.from, 'Send the new email in format: email: email@email.com');
    }

    // Handle "email:" command to add a new email
    else if (bodyLower.startsWith('email:') || bodyLower.startsWith('#')) {
        let parts = bodyLower.split(' ');
        let newEmail = parts[1].toLocaleLowerCase();
        if (!newEmail.includes('@')) {
            newEmail += '@gmail.com';
        }
        if (isValidEmail(newEmail)) {
            if (!newEmails) newEmails = [];
            newEmails.push(newEmail);
            saveNewEmails();
            client.sendMessage(message.from, `Saved new email: ${newEmail}`);
        } else {
            client.sendMessage(message.from, 'Invalid email format. Please use: email: email@email.com');
        }
    }

    // Handle "حذف " command to delete emails from new emails list
    else if (bodyLower.startsWith('حذف ')) {
        const emailsString = message.body.slice(4).trim();
        const emails = emailsString.split(/[\s,;\r\n]+/).filter(Boolean).map(email => email.toLowerCase());
        const validEmails = emails.filter(email => email.includes('@'));

        let deletedEmails = [];
        validEmails.forEach(email => {
            const index = newEmails.indexOf(email);
            if (index !== -1) {
                newEmails.splice(index, 1);
                deletedEmails.push(email);
            }
        });

        saveNewEmails();
        client.sendMessage(message.from, `Deleted ${deletedEmails.join(', ')} from new emails.`);
    }
});

