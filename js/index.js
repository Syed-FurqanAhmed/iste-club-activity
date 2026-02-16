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

    // ===== PAGE PRELOADER =====
    const preloader = document.getElementById('preloader');
    if (preloader) {
        setTimeout(() => {
            preloader.classList.add('hidden');
        }, 800);
    }
});

// ===== SCROLL PROGRESS BAR =====
const scrollProgress = document.getElementById('scrollProgress');

function updateScrollProgress() {
    const scrollTop = window.scrollY;
    const docHeight = document.documentElement.scrollHeight - window.innerHeight;
    const scrollPercent = (scrollTop / docHeight) * 100;
    if (scrollProgress) {
        scrollProgress.style.width = scrollPercent + '%';
    }
}

window.addEventListener('scroll', updateScrollProgress);

// ===== BACK TO TOP BUTTON =====
const backToTop = document.getElementById('backToTop');

function toggleBackToTop() {
    if (backToTop) {
        backToTop.classList.toggle('visible', window.scrollY > 300);
    }
}

if (backToTop) {
    backToTop.addEventListener('click', () => {
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });
}

window.addEventListener('scroll', toggleBackToTop);

// Navbar scroll effect
window.addEventListener('scroll', function () {
    const navbar = document.getElementById('navbar');
    navbar.classList.toggle('scrolled', window.scrollY > 80);
});

// ===== SCROLL SPY - Active nav link based on section =====
function updateActiveNavLink() {
    const sections = document.querySelectorAll('section[id], .hero');
    const navLinks = document.querySelectorAll('.nav-links a:not(.nav-cta)');
    
    let currentSection = '';
    const scrollPosition = window.scrollY + 150; // Offset for navbar height
    
    sections.forEach(section => {
        const sectionTop = section.offsetTop;
        const sectionHeight = section.offsetHeight;
        const sectionId = section.getAttribute('id') || 'main-content';
        
        if (scrollPosition >= sectionTop && scrollPosition < sectionTop + sectionHeight) {
            currentSection = sectionId;
        }
    });
    
    // Map section IDs to nav href
    const sectionToNav = {
        'main-content': '#',
        'hero': '#',
        'about': '#about',
        'activity': '#activity',
        'winners': '#winners',
        'gallery': '#gallery',
        'team': '#team'
    };
    
    const activeHref = sectionToNav[currentSection] || '#';
    
    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === activeHref) {
            link.classList.add('active');
        }
    });
}

window.addEventListener('scroll', updateActiveNavLink);
window.addEventListener('load', updateActiveNavLink);

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

// ===== ANIMATED NUMBER COUNTER =====
function animateNumber(el, target, suffix = '', duration = 2000) {
    const startTime = performance.now();
    const startValue = 0;
    
    function easeOutExpo(t) {
        return t === 1 ? 1 : 1 - Math.pow(2, -10 * t);
    }
    
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const easedProgress = easeOutExpo(progress);
        const currentValue = Math.floor(startValue + (target - startValue) * easedProgress);
        
        el.textContent = currentValue + suffix;
        
        if (progress < 1) {
            requestAnimationFrame(update);
        } else {
            el.textContent = target + suffix;
        }
    }
    
    requestAnimationFrame(update);
}

// Initialize stats counter animation
function initStatsCounter() {
    const statsSection = document.querySelector('.stats-bar');
    if (!statsSection) return;
    
    let hasAnimated = false;
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting && !hasAnimated) {
                hasAnimated = true;
                const statNumbers = statsSection.querySelectorAll('.stat-number');
                statNumbers.forEach((stat, index) => {
                    const text = stat.textContent.trim();
                    const match = text.match(/^(\d+)(.*)$/);
                    if (match) {
                        const number = parseInt(match[1]);
                        const suffix = match[2] || '';
                        stat.textContent = '0' + suffix;
                        setTimeout(() => {
                            animateNumber(stat, number, suffix, 2000);
                        }, index * 150); // Stagger animation
                    }
                });
            }
        });
    }, { threshold: 0.3 });
    
    observer.observe(statsSection);
}

// ===== GALLERY REVEAL ANIMATION =====
function initGalleryReveal() {
    const galleryItems = document.querySelectorAll('.gallery-item');
    if (!galleryItems.length) return;
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('revealed');
                observer.unobserve(entry.target);
            }
        });
    }, { 
        threshold: 0.2,
        rootMargin: '0px 0px -50px 0px'
    });
    
    galleryItems.forEach((item, index) => {
        item.style.setProperty('--item-index', index);
        observer.observe(item);
    });
}

// ===== WINNER PODIUM ANIMATION =====
function initWinnerPodium() {
    const winnersGrid = document.querySelector('.winners-grid');
    if (!winnersGrid) return;
    
    let hasAnimated = false;
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting && !hasAnimated) {
                hasAnimated = true;
                // Trigger podium rise: Bronze (3rd) → Silver (2nd) → Gold (1st)
                const winnerCards = winnersGrid.querySelectorAll('.winner-card');
                winnerCards.forEach(card => {
                    card.classList.add('podium-rise');
                });
            }
        });
    }, { threshold: 0.3 });
    
    observer.observe(winnersGrid);
}

// ===== LIGHTBOX SWIPE GESTURES =====
function initLightboxSwipe() {
    const imageModal = document.getElementById('imageModal');
    if (!imageModal) return;
    
    let touchStartX = 0;
    let touchEndX = 0;
    let touchStartY = 0;
    let touchEndY = 0;
    const minSwipeDistance = 50;
    
    // Get all gallery images for navigation
    function getGalleryImages() {
        return Array.from(document.querySelectorAll('.gallery-item img'));
    }
    
    function getCurrentImageIndex() {
        const modalImg = document.getElementById('modalImage');
        const images = getGalleryImages();
        return images.findIndex(img => img.src === modalImg.src);
    }
    
    function navigateImage(direction) {
        const images = getGalleryImages();
        const currentIndex = getCurrentImageIndex();
        let newIndex;
        
        if (direction === 'next') {
            newIndex = (currentIndex + 1) % images.length;
        } else {
            newIndex = (currentIndex - 1 + images.length) % images.length;
        }
        
        const modalImg = document.getElementById('modalImage');
        modalImg.style.opacity = '0';
        modalImg.style.transform = direction === 'next' ? 'translateX(-30px)' : 'translateX(30px)';
        
        setTimeout(() => {
            modalImg.src = images[newIndex].src;
            modalImg.style.transform = direction === 'next' ? 'translateX(30px)' : 'translateX(-30px)';
            
            requestAnimationFrame(() => {
                modalImg.style.opacity = '1';
                modalImg.style.transform = 'translateX(0)';
            });
        }, 150);
    }
    
    // Expose navigateImage globally for button onclick
    window.navigateLightbox = navigateImage;
    
    // Touch events for swipe
    imageModal.addEventListener('touchstart', (e) => {
        touchStartX = e.changedTouches[0].screenX;
        touchStartY = e.changedTouches[0].screenY;
    }, { passive: true });
    
    imageModal.addEventListener('touchend', (e) => {
        touchEndX = e.changedTouches[0].screenX;
        touchEndY = e.changedTouches[0].screenY;
        handleSwipe();
    });
    
    function handleSwipe() {
        const diffX = touchEndX - touchStartX;
        const diffY = touchEndY - touchStartY;
        
        // Only trigger if horizontal swipe is more significant than vertical
        if (Math.abs(diffX) > Math.abs(diffY) && Math.abs(diffX) > minSwipeDistance) {
            if (diffX > 0) {
                navigateImage('prev');
            } else {
                navigateImage('next');
            }
        }
    }
    
    // Keyboard navigation
    document.addEventListener('keydown', (e) => {
        if (!imageModal.classList.contains('active')) return;
        
        if (e.key === 'ArrowRight') {
            navigateImage('next');
        } else if (e.key === 'ArrowLeft') {
            navigateImage('prev');
        } else if (e.key === 'Escape') {
            closeImageModal();
        }
    });
}

// Initialize all enhanced animations
document.addEventListener('DOMContentLoaded', function() {
    initStatsCounter();
    initGalleryReveal();
    initWinnerPodium();
    initLightboxSwipe();
});

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
    let galleryAutoScrollInterval;

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

    // ===== GALLERY AUTO-SCROLL =====
    function autoScrollGallery() {
        const scrollLeft = galleryScroll.scrollLeft;
        const maxScroll = galleryScroll.scrollWidth - galleryScroll.clientWidth;

        if (scrollLeft >= maxScroll - 10) {
            // At the end, scroll back to start
            galleryScroll.scrollTo({ left: 0, behavior: 'smooth' });
        } else {
            // Scroll to next item
            galleryScroll.scrollBy({ left: scrollAmount, behavior: 'smooth' });
        }
    }

    function startGalleryAutoScroll() {
        galleryAutoScrollInterval = setInterval(autoScrollGallery, 4000);
    }

    function stopGalleryAutoScroll() {
        clearInterval(galleryAutoScrollInterval);
    }

    // Start auto-scroll
    startGalleryAutoScroll();

    // Pause on hover, resume on mouse leave
    galleryScroll.addEventListener('mouseenter', stopGalleryAutoScroll);
    galleryScroll.addEventListener('mouseleave', startGalleryAutoScroll);

    // Reset auto-scroll on manual navigation
    galleryPrev.addEventListener('click', function () {
        stopGalleryAutoScroll();
        startGalleryAutoScroll();
    });
    galleryNext.addEventListener('click', function () {
        stopGalleryAutoScroll();
        startGalleryAutoScroll();
    });
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

            // Scroll to error field
            teamNameInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
            setTimeout(() => teamNameInput.focus(), 300);

            // Increment error count for dynamic cooldown
            if (window.ISTESecurity && window.ISTESecurity.registrationLimiter) {
                window.ISTESecurity.registrationLimiter.incrementErrorCount();
            }

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
            eventCode: activeEvent,  // Dynamic routing from admin config (must be 'eventCode' per firestore.rules)
            member1: {
                name: formData.member1Name,
                usn: formData.member1USN,
                dept: formData.member1Dept,
                semester: formData.member1Sem
            },
            member1Name: formData.member1Name,  // Required by firestore.rules
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
            status: 'Pending'  // Must be 'Pending' with capital P per firestore.rules
        });

        document.getElementById('registrationForm').style.display = 'none';
        document.getElementById('formSuccess').classList.add('show');
        console.log('[App] Registration successful for team:', formData.teamName);

        // Reset error count on successful registration
        if (window.ISTESecurity && window.ISTESecurity.registrationLimiter) {
            window.ISTESecurity.registrationLimiter.resetErrorCount();
        }

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

        // Increment error count
        if (window.ISTESecurity && window.ISTESecurity.registrationLimiter) {
            window.ISTESecurity.registrationLimiter.incrementErrorCount();
        }

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

// ===== TESTIMONIAL CAROUSEL =====
let testimonialIndex = 0;
const testimonialTrack = document.getElementById('testimonialTrack');
const testimonialDots = document.querySelectorAll('.testimonial-dot');
let testimonialAutoSlide;

function updateTestimonialSlide() {
    if (testimonialTrack) {
        testimonialTrack.style.transform = `translateX(-${testimonialIndex * 100}%)`;
    }
    testimonialDots.forEach((dot, index) => {
        dot.classList.toggle('active', index === testimonialIndex);
    });
}

function nextTestimonial() {
    testimonialIndex = (testimonialIndex + 1) % testimonialDots.length;
    updateTestimonialSlide();
}

// Auto-slide testimonials every 5 seconds
function startTestimonialAutoSlide() {
    testimonialAutoSlide = setInterval(nextTestimonial, 5000);
}

if (testimonialTrack) {
    startTestimonialAutoSlide();

    // Click on dots to navigate
    testimonialDots.forEach((dot, index) => {
        dot.addEventListener('click', () => {
            testimonialIndex = index;
            updateTestimonialSlide();
            clearInterval(testimonialAutoSlide);
            startTestimonialAutoSlide();
        });
    });
}

// ===== TEAM TABS =====
const teamTabs = document.querySelectorAll('.team-tab');
const teamPanels = document.querySelectorAll('.team-panel');

teamTabs.forEach(tab => {
    tab.addEventListener('click', () => {
        const targetPanel = tab.getAttribute('data-tab');
        
        // Remove active from all tabs and panels
        teamTabs.forEach(t => t.classList.remove('active'));
        teamPanels.forEach(p => p.classList.remove('active'));
        
        // Add active to clicked tab and corresponding panel
        tab.classList.add('active');
        document.getElementById(`panel-${targetPanel}`).classList.add('active');
    });
});

// ===== LOAD TEAM FROM FIREBASE =====
async function loadTeamFromFirebase() {
    // Check if Firebase is available
    if (typeof firebase === 'undefined' || !window.firebaseConfig) {
        console.warn('Firebase not available for team loading');
        return;
    }
    
    try {
        // Initialize Firebase if not already done
        if (!firebase.apps.length) {
            firebase.initializeApp(window.firebaseConfig);
        }
        const db = firebase.firestore();
        
        // Get all team members ordered by 'order' field
        const snapshot = await db.collection('teamMembers').orderBy('order', 'asc').get();
        
        if (snapshot.empty) {
            // No team members found, show placeholder message
            ['faculty', 'core', 'volunteers'].forEach(category => {
                const grid = document.getElementById(`team-grid-${category}`);
                if (grid) {
                    grid.innerHTML = '<p style="text-align: center; color: var(--text-muted); padding: 2rem;">No team members added yet.</p>';
                }
            });
            return;
        }
        
        // Group members by category
        const members = { faculty: [], core: [], volunteers: [] };
        snapshot.forEach(doc => {
            const data = doc.data();
            if (members[data.category]) {
                members[data.category].push(data);
            }
        });
        
        // Role class mapping
        const getRoleClass = (role) => {
            const roleLower = role.toLowerCase();
            if (roleLower.includes('president') || roleLower.includes('hod') || roleLower.includes('principal')) return 'role-president';
            if (roleLower.includes('vice') || roleLower.includes('coordinator')) return 'role-vp';
            if (roleLower.includes('tech') || roleLower.includes('developer')) return 'role-tech';
            if (roleLower.includes('design') || roleLower.includes('creative')) return 'role-design';
            if (roleLower.includes('event') || roleLower.includes('management')) return 'role-event';
            if (roleLower.includes('social') || roleLower.includes('media') || roleLower.includes('content')) return 'role-social';
            return 'role-tech'; // default
        };
        
        // Escape HTML for security
        const escapeHtml = (str) => {
            if (!str) return '';
            const div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        };
        
        // Render members for each category
        Object.keys(members).forEach(category => {
            const grid = document.getElementById(`team-grid-${category}`);
            if (!grid) return;
            
            if (members[category].length === 0) {
                grid.innerHTML = '<p style="text-align: center; color: var(--text-muted); padding: 2rem;">No team members in this category.</p>';
                return;
            }
            
            grid.innerHTML = members[category].map(member => {
                const roleClass = getRoleClass(member.role);
                const socials = member.socials || {};
                
                // Build social links
                let socialLinksHtml = '';
                if (socials.linkedin) {
                    socialLinksHtml += `<a href="${escapeHtml(socials.linkedin)}" target="_blank" rel="noopener" title="LinkedIn">
                        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z"/></svg>
                    </a>`;
                }
                if (socials.github) {
                    socialLinksHtml += `<a href="${escapeHtml(socials.github)}" target="_blank" rel="noopener" title="GitHub">
                        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
                    </a>`;
                }
                if (socials.email) {
                    socialLinksHtml += `<a href="mailto:${escapeHtml(socials.email)}" title="Email">
                        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M0 3v18h24v-18h-24zm21.518 2l-9.518 7.713-9.518-7.713h19.036zm-19.518 14v-11.817l10 8.104 10-8.104v11.817h-20z"/></svg>
                    </a>`;
                }
                // Build image path - prepend images/ if not already a full URL
                const imagePath = member.imageUrl 
                    ? (member.imageUrl.startsWith('http') ? member.imageUrl : `images/${member.imageUrl}`)
                    : '';
                
                return `
                <div class="team-card">
                    <div class="team-avatar">
                        ${member.imageUrl 
                            ? `<img src="${escapeHtml(imagePath)}" alt="${escapeHtml(member.name)}" loading="lazy" onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';">
                               <div class="avatar-placeholder" style="display:none;">${escapeHtml(member.name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0,2))}</div>`
                            : `<div class="avatar-placeholder">${escapeHtml(member.name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0,2))}</div>`
                        }
                    </div>
                    <div class="team-info">
                        <h4>${escapeHtml(member.name)}</h4>
                        <span class="team-role ${roleClass}">${escapeHtml(member.role)}</span>
                        ${member.department ? `<p class="team-dept">${escapeHtml(member.department)}</p>` : ''}
                        ${socialLinksHtml ? `<div class="team-socials">${socialLinksHtml}</div>` : ''}
                    </div>
                </div>
                `;
            }).join('');
        });
        
    } catch (error) {
        console.error('Error loading team members:', error);
        ['faculty', 'core', 'volunteers'].forEach(category => {
            const grid = document.getElementById(`team-grid-${category}`);
            if (grid) {
                grid.innerHTML = '<p style="text-align: center; color: var(--accent-red); padding: 2rem;">Error loading team members.</p>';
            }
        });
    }
}

// Load team members when DOM is ready
document.addEventListener('DOMContentLoaded', loadTeamFromFirebase);

// ===== FEEDBACK WIDGET =====
document.addEventListener('DOMContentLoaded', function() {
    const emojiButtons = document.querySelectorAll('.emoji-btn');
    const feedbackForm = document.getElementById('feedbackForm');
    const feedbackSuccess = document.getElementById('feedbackSuccess');
    const feedbackHeader = document.querySelector('.feedback-header');
    const feedbackWidget = document.querySelector('.feedback-widget');
    const feedbackSection = document.querySelector('.feedback-section');
    const submitBtn = document.getElementById('submitFeedback');
    const feedbackText = document.getElementById('feedbackText');
    
    let selectedRating = 0;
    
    // Function to reset/close feedback form
    function closeFeedbackForm() {
        if (feedbackForm) feedbackForm.classList.remove('active');
        emojiButtons.forEach(b => b.classList.remove('selected'));
        if (feedbackText) feedbackText.value = '';
        selectedRating = 0;
    }
    
    // Handle emoji selection
    emojiButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            // Remove selected class from all
            emojiButtons.forEach(b => b.classList.remove('selected'));
            // Add to clicked one
            this.classList.add('selected');
            selectedRating = parseInt(this.dataset.rating);
            // Show feedback form
            if (feedbackForm) {
                feedbackForm.classList.add('active');
            }
        });
    });
    
    // Close on Escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && feedbackForm && feedbackForm.classList.contains('active')) {
            closeFeedbackForm();
        }
    });
    
    // Close when clicking outside the widget (on the section background)
    if (feedbackSection) {
        feedbackSection.addEventListener('click', function(e) {
            // Only close if clicking directly on section, not on widget
            if (e.target === feedbackSection && feedbackForm && feedbackForm.classList.contains('active')) {
                closeFeedbackForm();
            }
        });
    }
    
    // Handle submit
    if (submitBtn) {
        submitBtn.addEventListener('click', async function() {
            const feedback = feedbackText ? feedbackText.value.trim() : '';
            
            if (selectedRating === 0) {
                return;
            }
            
            // Disable button and show loading
            submitBtn.disabled = true;
            submitBtn.textContent = 'Sending...';
            
            try {
                // Save to Firestore 'feedback' collection
                await db.collection('feedback').add({
                    rating: selectedRating,
                    feedback: feedback,
                    timestamp: firebase.firestore.FieldValue.serverTimestamp(),
                    page: 'index',
                    userAgent: navigator.userAgent
                });
                
                // Show success
                if (feedbackHeader) feedbackHeader.style.display = 'none';
                if (feedbackForm) feedbackForm.style.display = 'none';
                if (feedbackSuccess) feedbackSuccess.classList.add('active');
                
                // Reset after 3 seconds
                setTimeout(() => {
                    if (feedbackSuccess) feedbackSuccess.classList.remove('active');
                    if (feedbackHeader) feedbackHeader.style.display = 'flex';
                    if (feedbackForm) feedbackForm.classList.remove('active');
                    emojiButtons.forEach(b => b.classList.remove('selected'));
                    if (feedbackText) feedbackText.value = '';
                    selectedRating = 0;
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Send Feedback';
                }, 3000);
                
            } catch (error) {
                console.error('Error submitting feedback:', error);
                submitBtn.disabled = false;
                submitBtn.textContent = 'Try Again';
            }
        });
    }
});

