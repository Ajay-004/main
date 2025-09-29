document.addEventListener('DOMContentLoaded', () => {

    // --- MASTER TRANSLATIONS OBJECT ---
    const translations = {
        introPage: {
            en: { mainTitle: "Elevate Your Farming", subtitle: "SMART SOLUTIONS FOR MODERN AGRICULTURE", description: "Get AI advice and weather updates to optimize your crops.", featureAI: "AI Assistant", featureHealth: "Plant Health", featureWeather: "Weather", getStarted: "Get Started" },
            ta: { mainTitle: "உங்கள் விவசாயத்தை மேம்படுத்துங்கள்", subtitle: "நவீன விவசாயத்திற்கான ஸ்மார்ட் தீர்வுகள்", description: "உங்கள் பயிர்களை மேம்படுத்த AI ஆலோசனைகளையும் வானிலை அறிவிப்புகளையும் பெறுங்கள்.", featureAI: "AI உதவியாளர்", featureHealth: "பயிர் ஆரோக்கியம்", featureWeather: "வானிலை", getStarted: "தொடங்கவும்" },
            ml: { mainTitle: "നിങ്ങളുടെ കൃഷി മെച്ചപ്പെടുത്തുക", subtitle: "ആധുനിക കൃഷിക്കുള്ള മികച്ച പരിഹാരങ്ങൾ", description: "നിങ്ങളുടെ വിളകൾ ഒപ്റ്റിമൈസ് ചെയ്യുന്നതിന് AI ഉപദേശവും കാലാവസ്ഥാ അപ്‌ഡേറ്റുകളും നേടുക.", featureAI: "AI അസിസ്റ്റന്റ്", featureHealth: "സസ്യ ആരോഗ്യം", featureWeather: "കാലാവസ്ഥ", getStarted: "തുടങ്ങുക" }
        },
        loginPage: {
            en: { title: "Welcome Back!", subtitle: "Please enter your details to sign in.", labelUser: "Username", labelPass: "Password", submitBtn: "Sign In", footerText: "Don't have an account?", footerLink: "Sign Up" },
            ta: { title: "மீண்டும் வருக!", subtitle: "உள்நுழைய உங்கள் விவரங்களை உள்ளிடவும்.", labelUser: "பயனர்பெயர்", labelPass: "கடவுச்சொல்", submitBtn: "உள்நுழைக", footerText: "கணக்கு இல்லையா?", footerLink: "புதிய கணக்கு" },
            ml: { title: "വീണ്ടും സ്വാഗതം!", subtitle: "സൈൻ ഇൻ ചെയ്യുന്നതിന് നിങ്ങളുടെ വിശദാംശങ്ങൾ നൽകുക.", labelUser: "ഉപയോക്തൃനാമം", labelPass: "പാസ്വേഡ്", submitBtn: "സൈൻ ഇൻ ചെയ്യുക", footerText: "അക്കൗണ്ട് ഇല്ലേ?", footerLink: "സൈൻ അപ്പ് ചെയ്യുക" }
        },
        signupPage: {
            en: { title: "Create an Account", subtitle: "Fill in the details below to get started.", labelUser: "Username", labelEmail: "Email", labelPhone: "Phone Number", labelPass: "Password", labelConfirm: "Confirm Password", labelState: "State", selectState: "Select your state", submitBtn: "Submit", footerText: "Already have an account?", footerLink: "Sign In", loaderText: "Creating your account..." },
            ta: { title: "புதிய கணக்கை உருவாக்கு", subtitle: "தொடங்குவதற்கு கீழே உள்ள விவரங்களை நிரப்பவும்.", labelUser: "பயனர்பெயர்", labelEmail: "மின்னஞ்சல்", labelPhone: "தொலைபேசி எண்", labelPass: "கடவுச்சொல்", labelConfirm: "கடவுச்சொல்லை உறுதிப்படுத்தவும்", labelState: "மாநிலம்", selectState: "உங்கள் மாநிலத்தைத் தேர்ந்தெடுக்கவும்", submitBtn: "சமர்ப்பி", footerText: "ஏற்கனவே கணக்கு உள்ளதா?", footerLink: "உள்நுழைக", loaderText: "உங்கள் கணக்கு உருவாக்கப்படுகிறது..." },
            ml: { title: "അക്കൗണ്ട് ഉണ്ടാക്കുക", subtitle: "തുടങ്ങുന്നതിന് താഴെയുള്ള വിശദാംശങ്ങൾ പൂരിപ്പിക്കുക.", labelUser: "ഉപയോക്തൃനാമം", labelEmail: "ഇമെയിൽ", labelPhone: "ഫോൺ നമ്പർ", labelPass: "പാസ്വേഡ്", labelConfirm: "പാസ്വേഡ് സ്ഥിരീകരിക്കുക", labelState: "സംസ്ഥാനം", selectState: "നിങ്ങളുടെ സംസ്ഥാനം തിരഞ്ഞെടുക്കുക", submitBtn: "സമർപ്പിക്കുക", footerText: "ഇതിനകം അക്കൗണ്ട് ഉണ്ടോ?", footerLink: "സൈൻ ഇൻ ചെയ്യുക", loaderText: "നിങ്ങളുടെ അക്കൗണ്ട് നിർമ്മിക്കുന്നു..." }
        },
        otpPage: {
            en: { title: "OTP Verification", subtitle: "A 6-digit code has been sent to your mobile number.", labelOtp: "Enter OTP", timerText: "Time remaining:", submitBtn: "Verify", footerText: "Didn't receive the OTP?", resendBtn: "Resend OTP" },
            ta: { title: "OTP சரிபார்ப்பு", subtitle: "6 இலக்க குறியீடு உங்கள் மொபைல் எண்ணுக்கு அனுப்பப்பட்டுள்ளது.", labelOtp: "OTP-ஐ உள்ளிடவும்", timerText: "மீதமுள்ள நேரம்:", submitBtn: "சரிபார்க்கவும்", footerText: "OTP வரவில்லையா?", resendBtn: "மீண்டும் அனுப்புக" },
            ml: { title: "OTP വെരിഫിക്കേഷൻ", subtitle: "നിങ്ങളുടെ മൊബൈൽ നമ്പറിലേക്ക് 6 അക്ക കോഡ് അയച്ചിട്ടുണ്ട്.", labelOtp: "OTP നൽകുക", timerText: "സമയം ശേഷിക്കുന്നു:", submitBtn: "സ്ഥിരീകരിക്കുക", footerText: "OTP ലഭിച്ചില്ലേ?", resendBtn: "വീണ്ടും അയയ്ക്കുക" }
        },
        indexPage: {
            en: { navAI: "AI Assistant", navHealth: "Plant Health", navWeather: "Weather", navMarket: "Market", heroSubtitle: "SMART FARMING SOLUTIONS FOR MODERN FARMERS", heroTitle: "AI-Powered Farming Advisory at Your Fingertips", featuresTitle: "Everything You Need for Smart Farming", featuresSubtitle: "From AI-powered plant diagnosis to real-time market updates, our platform helps you make informed decisions.", profileTitle: "Profile", labelUsername: "Username", labelEmail: "Email", labelPhone: "Phone Number", labelState: "State", labelTheme: "Theme" },
            ta: { navAI: "AI உதவியாளர்", navHealth: "பயிர் ஆரோக்கியம்", navWeather: "வானிலை", navMarket: "சந்தை", heroSubtitle: "நவீன விவசாயிகளுக்கான ஸ்மார்ட் விவசாய தீர்வுகள்", heroTitle: "செயற்கை நுண்ணறிவு விவசாய ஆலோசனை உங்கள் விரல் நுனியில்", featuresTitle: "ஸ்மார்ட் விவசாயத்திற்கு தேவையான அனைத்தும்", featuresSubtitle: "AI-இயங்கும் பயிர் நோய் கண்டறிதல் முதல் நிகழ்நேர சந்தை நிலவரங்கள் வரை, எங்கள் தளம் உங்களுக்கு தகவலறிந்த முடிவுகளை எடுக்க உதவுகிறது.", profileTitle: "சுயவிவரம்", labelUsername: "பயனர்பெயர்", labelEmail: "மின்னஞ்சல்", labelPhone: "தொலைபேசி எண்", labelState: "மாநிலம்", labelTheme: "தீம்" },
            ml: { navAI: "AI അസിസ്റ്റന്റ്", navHealth: "സസ്യ ആരോഗ്യം", navWeather: "കാലാവസ്ഥ", navMarket: "വിപണി", heroSubtitle: "ആധുനിക കർഷകർക്കുള്ള സ്മാർട്ട് ഫാർമിംഗ് സൊല്യൂഷനുകൾ", heroTitle: "AI-പവർഡ് കാർഷിക ഉപദേശം നിങ്ങളുടെ വിരൽത്തുമ്പിൽ", featuresTitle: "സ്മാർട്ട് കൃഷിക്ക് ആവശ്യമായതെല്ലാം", featuresSubtitle: "AI- പവർഡ് പ്ലാന്റ് ഡയഗ്നോസിസ് മുതൽ തത്സമയ മാർക്കറ്റ് അപ്‌ഡേറ്റുകൾ വരെ, അറിവോടെ തീരുമാനങ്ങൾ എടുക്കാൻ ഞങ്ങളുടെ പ്ലാറ്റ്ഫോം നിങ്ങളെ സഹായിക്കുന്നു.", profileTitle: "പ്രൊഫൈൽ", labelUsername: "ഉപയോക്തൃനാമം", labelEmail: "ഇമെയിൽ", labelPhone: "ഫോൺ നമ്പർ", labelState: "സംസ്ഥാനം", labelTheme: "തീം" }
        }
    };

    // --- REUSABLE LANGUAGE SWITCHER FUNCTION ---
    const initializeLanguageSwitcher = (pageKey, elementIds) => {
        const languageSelector = document.getElementById('language-selector');
        if (!languageSelector) return;

        const changeLanguage = (lang) => {
            const content = translations[pageKey][lang];
            for (const key in elementIds) {
                const element = document.getElementById(elementIds[key]);
                if (element) {
                    element.textContent = content[key];
                }
            }
        };

        languageSelector.addEventListener('change', (event) => changeLanguage(event.target.value));
        changeLanguage('en'); // Set default language
    };

    // --- PAGE SPECIFIC LOGIC ---

    // INTRO PAGE
    const introContent = document.querySelector('.intro-content');
    if (introContent) {
        initializeLanguageSwitcher('introPage', {
            mainTitle: 'main-title', subtitle: 'subtitle', description: 'description', featureAI: 'feature-ai', featureHealth: 'feature-health',
            featureWeather: 'feature-weather', getStarted: 'get-started-btn'
        });
        const getStartedBtn = document.getElementById('get-started-btn');
        const loaderOverlay = document.getElementById('loader-overlay');
        getStartedBtn.addEventListener('click', (event) => {
            event.preventDefault();
            loaderOverlay.style.display = 'flex';
            setTimeout(() => { window.location.href = getStartedBtn.href; }, 1500);
        });
    }

    // LOGIN PAGE
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        initializeLanguageSwitcher('loginPage', {
            title: 'form-title', subtitle: 'form-subtitle', labelUser: 'label-username', labelPass: 'label-password',
            submitBtn: 'submit-btn', footerText: 'footer-text', footerLink: 'footer-link'
        });
        loginForm.addEventListener('submit', (e) => { e.preventDefault(); window.location.href = 'index.html'; });
    }

    // SIGNUP PAGE
    const signupForm = document.getElementById('signup-form');
    if (signupForm) {
        initializeLanguageSwitcher('signupPage', {
            title: 'form-title', subtitle: 'form-subtitle', labelUser: 'label-username', labelEmail: 'label-email', labelPhone: 'label-phone',
            labelPass: 'label-password', labelConfirm: 'label-confirm-password', labelState: 'label-state', selectState: 'select-state-option',
            submitBtn: 'submit-btn', footerText: 'footer-text', footerLink: 'footer-link', loaderText: 'loader-message'
        });
        signupForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const password = document.getElementById('signup-password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            if (password !== confirmPassword) {
                alert("Passwords do not match!");
                return;
            }
            const loaderOverlay = document.getElementById('loader-overlay');
            loaderOverlay.style.display = 'flex';
            setTimeout(() => { window.location.href = 'otp.html'; }, 2500);
        });
    }

    // OTP PAGE
    const otpForm = document.getElementById('otp-form');
    if (otpForm) {
        initializeLanguageSwitcher('otpPage', {
            title: 'form-title', subtitle: 'form-subtitle', labelOtp: 'label-otp', timerText: 'timer-text',
            submitBtn: 'submit-btn', footerText: 'footer-text', resendBtn: 'resend-otp-btn'
        });
        otpForm.addEventListener('submit', (e) => { e.preventDefault(); window.location.href = 'index.html'; });
        const timerElement = document.getElementById('timer');
        const resendBtn = document.getElementById('resend-otp-btn');
        let timeLeft = 120;
        let timerInterval = setInterval(() => {
            if (timeLeft <= 0) {
                clearInterval(timerInterval);
                timerElement.textContent = "00:00";
                resendBtn.disabled = false;
            } else {
                timeLeft--;
                const minutes = Math.floor(timeLeft / 60);
                let seconds = timeLeft % 60;
                seconds = seconds < 10 ? '0' + seconds : seconds;
                timerElement.textContent = `${minutes}:${seconds}`;
            }
        }, 1000);
    }
    
    // INDEX PAGE (MAIN DASHBOARD)
    const profileBtn = document.getElementById('profile-btn');
    if (profileBtn) {
        initializeLanguageSwitcher('indexPage', {
            navAI: 'nav-ai', navHealth: 'nav-health', navWeather: 'nav-weather', navMarket: 'nav-market',
            heroSubtitle: 'hero-subtitle', heroTitle: 'hero-title', featuresTitle: 'features-title',
            featuresSubtitle: 'features-subtitle', profileTitle: 'profile-title', labelUsername: 'profile-label-username',
            labelEmail: 'profile-label-email', labelPhone: 'profile-label-phone', labelState: 'profile-label-state',
            labelTheme: 'profile-label-theme'
        });

        const profilePanel = document.getElementById('profile-panel');
        const closePanelBtn = document.getElementById('close-panel-btn');
        const overlay = document.getElementById('overlay');
        const themeToggleBtn = document.getElementById('theme-toggle-btn');
        const logoutBtn = document.getElementById('logout-btn');

        const openPanel = () => { profilePanel.classList.add('open'); overlay.classList.add('active'); };
        const closePanel = () => { profilePanel.classList.remove('open'); overlay.classList.remove('active'); };

        profileBtn.addEventListener('click', openPanel);
        closePanelBtn.addEventListener('click', closePanel);
        overlay.addEventListener('click', closePanel);

        themeToggleBtn.addEventListener('click', () => {
            document.body.classList.toggle('dark-mode');
            const icon = themeToggleBtn.querySelector('i');
            if (document.body.classList.contains('dark-mode')) {
                icon.classList.remove('fa-sun');
                icon.classList.add('fa-moon');
            } else {
                icon.classList.remove('fa-moon');
                icon.classList.add('fa-sun');
            }
        });
        
        logoutBtn.addEventListener('click', () => { window.location.href = 'login.html'; });
    }
});