document.addEventListener('DOMContentLoaded', () => {
    // Make sure this URL is correct (either localhost or your live Render URL)
    const backendUrl = "http://localhost:3000"; 

    // --- Theme Toggle ---
    const themeToggleBtn = document.getElementById('theme-toggle');
    const body = document.body;
    if (themeToggleBtn) {
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'light-mode') {
            body.classList.add('light-mode');
            themeToggleBtn.innerHTML = '<i class="fa-solid fa-moon"></i>';
        } else {
            body.classList.remove('light-mode');
            themeToggleBtn.innerHTML = '<i class="fa-solid fa-sun"></i>';
        }
        themeToggleBtn.addEventListener('click', () => {
            body.classList.toggle('light-mode');
            if (body.classList.contains('light-mode')) {
                themeToggleBtn.innerHTML = '<i class="fa-solid fa-moon"></i>';
                localStorage.setItem('theme', 'light-mode');
            } else {
                themeToggleBtn.innerHTML = '<i class="fa-solid fa-sun"></i>';
                localStorage.setItem('theme', 'dark-mode');
            }
        });
    }

    // --- Login Modal ---
    const loginBtn = document.getElementById('login-btn');
    const loginModal = document.getElementById('login-modal');
    if (loginBtn && loginModal) {
        const closeModalBtn = document.getElementById('close-modal-btn');
        const modalOverlay = document.getElementById('modal-overlay');
        const openModal = () => { modalOverlay.classList.add('show'); loginModal.classList.add('show'); };
        const closeModal = () => { modalOverlay.classList.remove('show'); loginModal.classList.remove('show'); };
        loginBtn.addEventListener('click', openModal);
        closeModalBtn.addEventListener('click', closeModal);
        modalOverlay.addEventListener('click', (e) => { if (e.target === modalOverlay) closeModal(); });
        document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && loginModal.classList.contains('show')) closeModal(); });
    }

    // --- Image Upload Functionality ---
    const uploadArea = document.getElementById('upload-area');
    if (uploadArea) {
        let imageUploadInput;

        const createUploader = () => {
            uploadArea.innerHTML = `
                <div class="upload-area-content">
                    <input type="file" id="image-upload" accept="image/jpeg, image/png" hidden>
                    <div class="upload-icon-large"><i class="fa-solid fa-cloud-arrow-up"></i></div>
                    <p><strong>Upload Crop Image</strong></p>
                    <p>Drag and drop, or click to browse</p>
                </div>
            `;
            imageUploadInput = document.getElementById('image-upload');
            const uploadContent = uploadArea.querySelector('.upload-area-content');
            uploadContent.addEventListener('click', () => imageUploadInput.click());
            imageUploadInput.addEventListener('change', () => handleFileSelect(imageUploadInput.files));
        };

        const handleFileSelect = (files) => {
            const file = files[0];
            if (!file) return;
            uploadArea.innerHTML = `<p>Generating caption, please wait... (First time may be slow)</p><div class="loader"></div>`;
            const formData = new FormData();
            formData.append('cropImage', file);

            fetch(`${backendUrl}/analyze-image`, { method: 'POST', body: formData })
                .then(response => {
                    if (!response.ok) {
                         // Get the error message from the backend and throw it
                        return response.json().then(err => { throw new Error(err.error) });
                    }
                    return response.json();
                })
                .then(data => {
                    displayAnalysis(file, data);
                })
                .catch(error => {
                    console.error('BLIP Error:', error);
                    uploadArea.innerHTML = `<p style="color: #e74c3c;">Error: ${error.message}</p>`;
                    setTimeout(createUploader, 4000);
                });
        };

        const displayAnalysis = (file, analysisData) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                uploadArea.innerHTML = `
                    <div class="image-preview-wrapper">
                        <img src="${e.target.result}" alt="Uploaded Crop Image" class="image-preview">
                        <button class="remove-image-btn" title="Remove Image"><i class="fa-solid fa-xmark"></i></button>
                    </div>
                    <div class="analysis-results">
                        <h3>Image Caption</h3>
                        <p>${analysisData.analysis}</p>
                    </div>`;
                uploadArea.querySelector('.remove-image-btn').addEventListener('click', createUploader);
            };
            reader.readAsDataURL(file);
        };
        
        createUploader();
    }

    // --- Chatbot & Voice-to-Text Functionality ---
    const sendBtn = document.getElementById('send-btn');
    const micBtn = document.getElementById('mic-btn');
    const chatInput = document.getElementById('chat-input');
    const chatMessages = document.getElementById('chat-messages');
    let mediaRecorder;
    let audioChunks = [];

    if (sendBtn) {
        const sendMessage = () => {
            const messageText = chatInput.value.trim();
            if (!messageText) return;
            addMessage(messageText, 'user');
            chatInput.value = '';

            fetch(`${backendUrl}/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: messageText }),
            })
            .then(res => res.json())
            .then(data => addMessage(data.reply, 'assistant'))
            .catch(error => console.error("Mistral Chat Error:", error));
        };
        sendBtn.addEventListener('click', sendMessage);
        chatInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendMessage(); });
    }

    if (micBtn) {
        micBtn.addEventListener('click', () => {
            if (!mediaRecorder || mediaRecorder.state === "inactive") {
                startRecording();
            } else {
                stopRecording();
            }
        });
    }

    function startRecording() {
        navigator.mediaDevices.getUserMedia({ audio: true })
            .then(stream => {
                mediaRecorder = new MediaRecorder(stream);
                mediaRecorder.start();
                micBtn.classList.add('recording');
                audioChunks = [];
                mediaRecorder.addEventListener("dataavailable", event => audioChunks.push(event.data));
                mediaRecorder.addEventListener("stop", () => {
                    const audioBlob = new Blob(audioChunks);
                    transcribeAudio(audioBlob);
                    stream.getTracks().forEach(track => track.stop());
                });
            })
            .catch(error => console.error("Microphone access error:", error));
    }

    function stopRecording() {
        mediaRecorder.stop();
        micBtn.classList.remove('recording');
    }

    function transcribeAudio(audioBlob) {
        chatInput.placeholder = "Transcribing with Whisper...";
        const formData = new FormData();
        formData.append("audio", audioBlob);

        fetch(`${backendUrl}/transcribe-audio`, {
            method: 'POST',
            body: formData,
        })
        .then(res => res.json())
        .then(data => {
            chatInput.value = data.transcription;
            chatInput.placeholder = "Ask a question...";
        })
        .catch(error => console.error("Whisper Transcription Error:", error));
    }

    function addMessage(text, sender) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message', sender);
        messageElement.textContent = text;
        chatMessages.appendChild(messageElement);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
});