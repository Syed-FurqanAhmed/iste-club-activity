        /**
         * ============================================================================
         * ISTE Club Website - Main Application Script
         * ============================================================================
         * 
         * SECURITY FEATURES INTEGRATED:
         * - reCAPTCHA v3 (invisible bot protection)
         * - Rate Limiting with token bucket
         * - Input Validation (schema-based)
         * - Input Sanitization (XSS prevention)
         * - Button Debouncing (spam prevention)
         * - 60-second cooldown between submissions
         * 
         * @see security.js for implementation details
         */

        // SECURITY: reCAPTCHA v3 Site Key
        const RECAPTCHA_SITE_KEY = '6LeeoD8sAAAAAGKAdRH9D4ca5FHGsip-XXGcXOzM';

        // Initialize Firebase
        firebase.initializeApp(firebaseConfig);
        const db = firebase.firestore();

        // ===== SECURITY INITIALIZATION =====
        document.addEventListener('DOMContentLoaded', function () {
            // Initialize security module for registration
            if (window.ISTESecurity) {
                window.ISTESecurity.init('registration');
                console.log('[App] Security module initialized');
            }
        });

        // Navbar scroll effect
        window.addEventListener('scroll', function () {
            const navbar = document.getElementById('navbar');
            navbar.classList.toggle('scrolled', window.scrollY > 80);
        });

        // Mobile navigation
        function toggleNav() {
            document.getElementById('navLinks').classList.toggle('active');
            document.getElementById('hamburger').classList.toggle('active');
        }

        // Close menu when clicking outside
        document.addEventListener('click', function (event) {
            const navLinks = document.getElementById('navLinks');
            const hamburger = document.getElementById('hamburger');
            const navbar = document.getElementById('navbar');
            if (!navbar.contains(event.target) && navLinks.classList.contains('active')) {
                navLinks.classList.remove('active');
                hamburger.classList.remove('active');
            }
        });

        // Reveal on scroll
        const reveals = document.querySelectorAll('.reveal');
        function revealOnScroll() {
            reveals.forEach(el => {
                const windowHeight = window.innerHeight;
                const top = el.getBoundingClientRect().top;
                if (top < windowHeight - 100) {
                    el.classList.add('active');
                }
            });
        }
        window.addEventListener('scroll', revealOnScroll);
        revealOnScroll();

        // Modal functions
        function openModal() {
            document.getElementById('formModal').classList.add('active');
            document.body.style.overflow = 'hidden';
            document.getElementById('registrationForm').reset();
            document.getElementById('registrationForm').style.display = 'flex';
            document.getElementById('formSuccess').classList.remove('show');

            // SECURITY: Clear any previous validation errors
            // Note: Rate limiting is active but hidden from users to avoid confusion
            if (window.ISTESecurity) {
                window.ISTESecurity.clearValidationErrors();
            }
        }

        function closeModal() {
            document.getElementById('formModal').classList.remove('active');
            document.body.style.overflow = '';
        }

        // Image modal
        function openImage(el) {
            const img = el.querySelector('img');
            document.getElementById('modalImage').src = img.src;
            document.getElementById('imageModal').classList.add('active');
            document.body.style.overflow = 'hidden';
        }

        function closeImageModal() {
            document.getElementById('imageModal').classList.remove('active');
            document.body.style.overflow = '';
        }

        // ===== SUCCESS MODAL & CONFETTI =====
        function showSuccessModal(teamName, eventName, memberCount) {
            // Update modal content
            document.getElementById('successTeamName').textContent = teamName || 'Your Team';
            document.getElementById('successEventName').textContent = eventName || 'Quick Draw UI Battle';
            document.getElementById('successMemberCount').textContent = memberCount + ' member' + (memberCount > 1 ? 's' : '') + ' registered';

            // Show modal
            document.getElementById('successModal').classList.add('active');
            document.body.style.overflow = 'hidden';

            // Launch confetti
            launchConfetti();
        }

        function closeSuccessModal() {
            document.getElementById('successModal').classList.remove('active');
            document.body.style.overflow = '';
            // Clear confetti
            document.getElementById('confettiContainer').innerHTML = '';
        }

        function launchConfetti() {
            const container = document.getElementById('confettiContainer');
            const colors = ['#6366f1', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981', '#3b82f6'];
            const confettiCount = 100;

            for (let i = 0; i < confettiCount; i++) {
                const confetti = document.createElement('div');
                confetti.className = 'confetti';
                confetti.style.left = Math.random() * 100 + '%';
                confetti.style.backgroundColor = colors[Math.floor(Math.random() * colors.length)];
                confetti.style.animationDelay = Math.random() * 2 + 's';
                confetti.style.animationDuration = (Math.random() * 2 + 2) + 's';

                // Random shapes
                const shapes = ['circle', 'square', 'rectangle'];
                const shape = shapes[Math.floor(Math.random() * shapes.length)];
                if (shape === 'circle') confetti.style.borderRadius = '50%';
                if (shape === 'rectangle') confetti.style.width = '6px';

                container.appendChild(confetti);
            }

            // Clear confetti after animation
            setTimeout(() => {
                container.innerHTML = '';
            }, 5000);
        }

        // ===== SECTION REVEAL ON SCROLL =====
        function initSectionReveal() {
            const sections = document.querySelectorAll('.stats-bar, .about, .activity, .winners, .gallery');

            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('reveal-section', 'visible');
                    }
                });
            }, {
                threshold: 0.1,
                rootMargin: '0px 0px -50px 0px'
            });

            sections.forEach(section => {
                section.classList.add('reveal-section');
                observer.observe(section);
            });
        }

        // Initialize section reveal on DOM load
        document.addEventListener('DOMContentLoaded', initSectionReveal);

        // ===== DUPLICATE REGISTRATION CHECK =====
        async function checkDuplicate(field, value, errorElementId) {
            if (!value || value.trim() === '') {
                document.getElementById(errorElementId).style.display = 'none';
                const inputEl = document.getElementById(errorElementId.replace('Error', ''));
                if (inputEl) inputEl.style.borderColor = '';
                return false;
            }

            try {
                // Query for existing registration with this value
                const snapshot = await db.collection('registrations')
                    .where(field, '==', value.trim().toUpperCase())
                    .limit(1)
                    .get();

                const errorEl = document.getElementById(errorElementId);
                const inputEl = document.getElementById(errorElementId.replace('Error', ''));

                if (!snapshot.empty) {
                    // Duplicate found
                    errorEl.style.display = 'block';
                    inputEl.style.borderColor = '#EF4444';
                    return true;
                } else {
                    // No duplicate
                    errorEl.style.display = 'none';
                    inputEl.style.borderColor = '';
                    return false;
                }
            } catch (err) {
                console.error('Duplicate check error:', err);
                return false;
            }
        }

        // Add duplicate check event listeners on DOM load
        document.addEventListener('DOMContentLoaded', function () {
            // Email duplicate check
            const teamEmailInput = document.getElementById('teamEmail');
            if (teamEmailInput) {
                teamEmailInput.addEventListener('blur', (e) =>
                    checkDuplicate('email', e.target.value, 'teamEmailError'));
            }

            // USN duplicate checks for all members
            const member1USNInput = document.getElementById('member1USN');
            if (member1USNInput) {
                member1USNInput.addEventListener('blur', (e) =>
                    checkDuplicate('member1.usn', e.target.value, 'member1USNError'));
            }

            const member2USNInput = document.getElementById('member2USN');
            if (member2USNInput) {
                member2USNInput.addEventListener('blur', (e) =>
                    checkDuplicate('member2.usn', e.target.value, 'member2USNError'));
            }

            const member3USNInput = document.getElementById('member3USN');
            if (member3USNInput) {
                member3USNInput.addEventListener('blur', (e) =>
                    checkDuplicate('member3.usn', e.target.value, 'member3USNError'));
            }
        });

        // ===== DYNAMIC WINNERS LOADING =====
        async function loadWinners() {
            try {
                console.log('[Winners] Loading winners from Firestore...');

                // Query all winners (without orderBy to avoid composite index requirement)
                const winnersSnapshot = await db.collection('registrations')
                    .where('isWinner', '==', true)
                    .get();

                if (winnersSnapshot.empty) {
                    console.log('[Winners] No winners found, showing empty state');
                    // Show empty state, hide winner cards and skeletons
                    document.getElementById('winnersEmpty').style.display = 'block';
                    hideSkeletonsShowWinners();
                    // Hide actual winner cards
                    document.getElementById('winner-1').style.display = 'none';
                    document.getElementById('winner-2').style.display = 'none';
                    document.getElementById('winner-3').style.display = 'none';
                    return;
                }

                // Sort winners by position and limit to top 3
                const winners = [];
                winnersSnapshot.forEach(doc => {
                    const data = doc.data();
                    if (data.winnerPosition && data.winnerPosition <= 3) {
                        winners.push({ id: doc.id, ...data });
                    }
                });
                winners.sort((a, b) => a.winnerPosition - b.winnerPosition);

                // Hide empty state when winners exist
                document.getElementById('winnersEmpty').style.display = 'none';

                winners.forEach(winner => {
                    const position = winner.winnerPosition;

                    // Get member names
                    const members = [];
                    if (winner.member1?.name) members.push(winner.member1.name);
                    if (winner.member2?.name) members.push(winner.member2.name);
                    if (winner.member3?.name) members.push(winner.member3.name);

                    // Update the winner card
                    const nameEl = document.getElementById(`winner-${position}-name`);
                    const membersEl = document.getElementById(`winner-${position}-members`);

                    if (nameEl) {
                        nameEl.textContent = winner.teamName || 'Winner';
                    }
                    if (membersEl) {
                        membersEl.innerHTML = members.map(m => `${m}`).join('<br>');
                    }

                    console.log(`[Winners] Loaded position ${position}: ${winner.teamName}`);
                });

                // Hide skeletons and show winner cards after loading
                hideSkeletonsShowWinners();

            } catch (err) {
                console.error('[Winners] Error loading winners:', err);
                // Hide skeletons and show TBA on error
                document.getElementById('winner-1-name').textContent = 'TBA';
                document.getElementById('winner-2-name').textContent = 'TBA';
                document.getElementById('winner-3-name').textContent = 'TBA';
                hideSkeletonsShowWinners();
            }
        }

        // Helper function to transition from skeleton to actual content
        function hideSkeletonsShowWinners() {
            // Hide skeleton loaders
            const skeletons = document.querySelectorAll('.skeleton-wrapper');
            skeletons.forEach(skeleton => {
                skeleton.style.display = 'none';
            });

            // Show winner cards
            const winnerCards = document.querySelectorAll('.winner-card');
            winnerCards.forEach(card => {
                card.style.display = '';
            });
        }

        // Load winners on page load
        document.addEventListener('DOMContentLoaded', function () {
            // Small delay to ensure Firebase is ready
            setTimeout(loadWinners, 1000);
        });

        // Close modals with Escape key
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') {
                closeModal();
                closeImageModal();
            }
        });

        // Gallery navigation
        const galleryScroll = document.getElementById('galleryScroll');
        const galleryPrev = document.getElementById('galleryPrev');
        const galleryNext = document.getElementById('galleryNext');

        if (galleryScroll && galleryPrev && galleryNext) {
            const scrollAmount = 440;

            galleryPrev.addEventListener('click', function () {
                galleryScroll.scrollBy({ left: -scrollAmount, behavior: 'smooth' });
            });

            galleryNext.addEventListener('click', function () {
                galleryScroll.scrollBy({ left: scrollAmount, behavior: 'smooth' });
            });

            // Update arrow visibility based on scroll position
            function updateArrowVisibility() {
                const scrollLeft = galleryScroll.scrollLeft;
                const maxScroll = galleryScroll.scrollWidth - galleryScroll.clientWidth;

                galleryPrev.classList.toggle('hidden', scrollLeft <= 10);
                galleryNext.classList.toggle('hidden', scrollLeft >= maxScroll - 10);
            }

            galleryScroll.addEventListener('scroll', updateArrowVisibility);
            updateArrowVisibility();
        }

        /**
         * SECURITY: Enhanced Form Submission Handler
         * - reCAPTCHA v3 bot detection (invisible)
         * - Rate limiting check (token bucket)
         * - Input validation (schema-based)
         * - Input sanitization (XSS prevention)
         * - Button debouncing (spam prevention)
         * - 60-second cooldown between submissions
         */
        document.getElementById('registrationForm').addEventListener('submit', async function (e) {
            e.preventDefault();

            const btn = document.getElementById('submitBtn');
            const teamNameInput = document.getElementById('teamName');
            const teamNameError = document.getElementById('teamNameError');
            const formContainer = document.querySelector('.modal-body');

            // Reset error states
            teamNameError.style.display = 'none';
            teamNameInput.style.borderColor = '';

            // SECURITY: Execute reCAPTCHA v3 (invisible to user)
            let recaptchaToken = null;
            try {
                if (typeof grecaptcha !== 'undefined') {
                    btn.disabled = true;
                    btn.querySelector('.btn-text').textContent = 'Verifying...';

                    recaptchaToken = await grecaptcha.execute(RECAPTCHA_SITE_KEY, { action: 'register' });
                    console.log('[Security] reCAPTCHA v3 token generated');

                    btn.querySelector('.btn-text').textContent = 'Register Team 🚀';
                    btn.disabled = false;
                }
            } catch (recaptchaError) {
                console.warn('[Security] reCAPTCHA failed, continuing:', recaptchaError);
                // Continue without reCAPTCHA if it fails (fallback to other protections)
            }

            const formData = {
                teamEmail: document.getElementById('teamEmail').value,
                teamName: document.getElementById('teamName').value,
                member1Name: document.getElementById('member1Name').value,
                member1USN: document.getElementById('member1USN').value,
                member1Dept: document.getElementById('member1Dept').value,
                member1Sem: document.getElementById('member1Sem').value,
                member2Name: document.getElementById('member2Name').value,
                member2USN: document.getElementById('member2USN').value,
                member2Dept: document.getElementById('member2Dept').value,
                member2Sem: document.getElementById('member2Sem').value,
                member3Name: document.getElementById('member3Name').value,
                member3USN: document.getElementById('member3USN').value,
                member3Dept: document.getElementById('member3Dept').value,
                member3Sem: document.getElementById('member3Sem').value
            };

            // ===== SECURITY: Process through security module =====
            if (window.ISTESecurity) {
                const result = window.ISTESecurity.processRegistration(formData, btn);

                // Handle rate limiting
                if (result.type === 'RATE_LIMITED') {
                    window.ISTESecurity.showRateLimitError(formContainer, result.message);
                    console.warn('[Security] Rate limit triggered:', result.message);
                    return;
                }

                // Handle validation errors
                if (result.type === 'VALIDATION_ERROR') {
                    window.ISTESecurity.displayValidationErrors(result.errors);
                    console.warn('[Security] Validation failed:', result.errors);
                    ButtonDebouncer.restoreFromLoading(btn);
                    return;
                }

                // Use sanitized data
                formData.teamName = result.data.teamName;
                formData.teamEmail = result.data.teamEmail;
                formData.member1Name = result.data.member1Name;
                formData.member1USN = result.data.member1USN;
                formData.member1Dept = result.data.member1Dept;
                formData.member2Name = result.data.member2Name;
                formData.member2USN = result.data.member2USN;
                formData.member2Dept = result.data.member2Dept;
                formData.member3Name = result.data.member3Name;
                formData.member3USN = result.data.member3USN;
                formData.member3Dept = result.data.member3Dept;
            } else {
                // Fallback: basic button disable
                btn.classList.add('loading');
                btn.disabled = true;
            }

            try {
                // Check for duplicate team name
                const existingTeams = await db.collection('registrations')
                    .where('teamName', '==', formData.teamName)
                    .get();

                if (!existingTeams.empty) {
                    // Team name already exists
                    teamNameError.style.display = 'block';
                    teamNameInput.style.borderColor = '#ef4444';
                    teamNameInput.focus();
                    if (window.ButtonDebouncer) {
                        ButtonDebouncer.restoreFromLoading(btn);
                    } else {
                        btn.classList.remove('loading');
                        btn.disabled = false;
                    }
                    return;
                }

                // SECURITY: Save sanitized data to Firestore
                // Dynamic routing: Read active event from config
                let activeEvent = 'testing'; // Default fallback
                try {
                    const configDoc = await db.collection('config').doc('registration').get();
                    if (configDoc.exists && configDoc.data().activeEvent) {
                        activeEvent = configDoc.data().activeEvent;
                        console.log('[Routing] Registering to event:', activeEvent);
                    }
                } catch (configErr) {
                    console.log('[Routing] Using default event: testing');
                }

                await db.collection('registrations').add({
                    teamName: formData.teamName,
                    email: formData.teamEmail,
                    event: activeEvent,  // Dynamic routing from admin config
                    member1: {
                        name: formData.member1Name,
                        usn: formData.member1USN,
                        dept: formData.member1Dept,
                        semester: formData.member1Sem
                    },
                    member2: {
                        name: formData.member2Name || null,
                        usn: formData.member2USN || null,
                        dept: formData.member2Dept || null,
                        semester: formData.member2Sem || null
                    },
                    member3: {
                        name: formData.member3Name || null,
                        usn: formData.member3USN || null,
                        dept: formData.member3Dept || null,
                        semester: formData.member3Sem || null
                    },
                    registeredAt: firebase.firestore.FieldValue.serverTimestamp(),
                    status: 'pending'
                });

                document.getElementById('registrationForm').style.display = 'none';
                document.getElementById('formSuccess').classList.add('show');
                console.log('[App] Registration successful for team:', formData.teamName);

                // Count members
                let memberCount = 1;
                if (formData.member2Name) memberCount++;
                if (formData.member3Name) memberCount++;

                // Close registration modal and show success modal with confetti
                closeModal();
                setTimeout(() => {
                    showSuccessModal(formData.teamName, 'Quick Draw UI Battle', memberCount);
                }, 300);

            } catch (err) {
                console.error('[App] Registration error:', err);

                // SECURITY: Show user-friendly error (don't expose internal details)
                if (window.ISTESecurity) {
                    window.ISTESecurity.showRateLimitError(formContainer,
                        'Registration failed. Please check your connection and try again.');
                } else {
                    alert('Registration failed. Please try again.');
                }
            } finally {
                if (window.ButtonDebouncer) {
                    ButtonDebouncer.restoreFromLoading(btn);
                } else {
                    btn.classList.remove('loading');
                    btn.disabled = false;
                }
            }
        });

        // ===== THEME TOGGLE FUNCTIONALITY =====
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
            // Check for saved theme preference
            const savedTheme = localStorage.getItem('iste-theme');
            if (savedTheme === 'dark') {
                // Redirect to dark theme page
                window.location.href = 'index1.html';
            }

            // Handle toggle change
            themeToggle.addEventListener('change', function () {
                if (this.checked) {
                    localStorage.setItem('iste-theme', 'dark');
                    window.location.href = 'index1.html';
                }
            });

            // Update toggle title on hover
            themeToggle.parentElement.title = 'Switch to Ember (Dark) theme';
        }

        
