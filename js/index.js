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

// SECURITY: reCAPTCHA v3 Site Key (centralized in config.js)
const RECAPTCHA_SITE_KEY = window.RECAPTCHA_SITE_KEY || '6LeeoD8sAAAAAGKAdRH9D4ca5FHGsip-XXGcXOzM';

// SECURITY: Debug logging disabled in production
const DEBUG_MODE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
const secureLog = (...args) => { if (DEBUG_MODE) console.log(...args); };

// Initialize Firebase with error handling
let db;
try {
    if (typeof firebase !== 'undefined' && typeof window.firebaseConfig !== 'undefined') {
        firebase.initializeApp(window.firebaseConfig);
        db = firebase.firestore();
        secureLog('[Firebase] Initialized successfully');
    } else {
        console.error('[Firebase] Configuration not found. Please create config.js from config.example.js');
        console.error('firebase defined:', typeof firebase !== 'undefined');
        console.error('firebaseConfig defined:', typeof window.firebaseConfig !== 'undefined');
    }
} catch (error) {
    console.error('[Firebase] Initialization error:', error);
}

// ===== SECURITY INITIALIZATION =====
document.addEventListener('DOMContentLoaded', function () {
    // Check if Firebase is configured
    if (!db) {
        secureLog('[App] Firebase not configured. Some features will be unavailable.');
        // Show a subtle warning banner (optional - you can remove this if you don't want visible warnings)
        const registerBtn = document.getElementById('registerBtn');
        if (registerBtn) {
            registerBtn.disabled = true;
            registerBtn.textContent = 'Registration Unavailable';
            registerBtn.title = 'Firebase configuration required';
        }
    }
    
    // Initialize security module for registration
    if (window.ISTESecurity) {
        window.ISTESecurity.init('registration');
        secureLog('[App] Security module initialized');
    }

    // ===== PAGE PRELOADER =====
    const preloader = document.getElementById('preloader');
    if (preloader) {
        setTimeout(() => {
            preloader.classList.add('hidden');
        }, 800);
    }
});

// ===== CACHED DOM ELEMENTS =====
const scrollProgress = document.getElementById('scrollProgress');
const backToTop = document.getElementById('backToTop');
const navbar = document.getElementById('navbar');

// ===== SCROLL HANDLERS =====
function updateScrollProgress() {
    if (!scrollProgress) return;
    const docHeight = document.documentElement.scrollHeight - window.innerHeight;
    scrollProgress.style.width = `${(window.scrollY / docHeight) * 100}%`;
}

function toggleBackToTop() {
    if (backToTop) {
        backToTop.classList.toggle('visible', window.scrollY > 300);
    }
}

function updateNavbarScroll() {
    if (navbar) {
        navbar.classList.toggle('scrolled', window.scrollY > 80);
    }
}

// Unified scroll handler for better performance
function handleScroll() {
    updateScrollProgress();
    toggleBackToTop();
    updateNavbarScroll();
}

window.addEventListener('scroll', handleScroll);

if (backToTop) {
    backToTop.addEventListener('click', () => {
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });
}

// ===== SCROLL SPY - Active nav link based on section =====
const NAV_OFFSET = 150;
const SECTION_TO_NAV = {
    'main-content': '#',
    'hero': '#',
    'about': '#about',
    'activity': '#activity',
    'winners': '#winners',
    'gallery': '#gallery',
    'team': '#team'
};

function updateActiveNavLink() {
    const sections = document.querySelectorAll('section[id], .hero');
    const navLinks = document.querySelectorAll('.nav-links a:not(.nav-cta)');
    const scrollPosition = window.scrollY + NAV_OFFSET;
    
    // Find current section
    const currentSection = Array.from(sections).find(section => {
        const top = section.offsetTop;
        return scrollPosition >= top && scrollPosition < top + section.offsetHeight;
    });
    
    const activeHref = SECTION_TO_NAV[currentSection?.id || 'main-content'] || '#';
    
    navLinks.forEach(link => {
        link.classList.toggle('active', link.getAttribute('href') === activeHref);
    });
}

window.addEventListener('scroll', updateActiveNavLink);
window.addEventListener('load', updateActiveNavLink);

// Mobile navigation
function toggleNav() {
    const navLinks = document.getElementById('navLinks');
    const hamburger = document.getElementById('hamburger');
    const isExpanded = navLinks.classList.toggle('active');
    hamburger.classList.toggle('active');
    hamburger.setAttribute('aria-expanded', isExpanded);
}

// Close menu when clicking outside
document.addEventListener('click', function (event) {
    const navLinks = document.getElementById('navLinks');
    const hamburger = document.getElementById('hamburger');
    const navbar = document.getElementById('navbar');
    if (!navbar.contains(event.target) && navLinks.classList.contains('active')) {
        navLinks.classList.remove('active');
        hamburger.classList.remove('active');
        hamburger.setAttribute('aria-expanded', 'false');
    }
});

// Reveal on scroll
const reveals = document.querySelectorAll('.reveal');
const REVEAL_THRESHOLD = 100;

function revealOnScroll() {
    const windowHeight = window.innerHeight;
    reveals.forEach(el => {
        if (el.getBoundingClientRect().top < windowHeight - REVEAL_THRESHOLD) {
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

    // Reset all custom dropdowns to placeholder state
    resetAllCustomSelects();

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
let currentFeaturedEventName = '';

function showSuccessModal(teamName, eventName, memberCount) {
    const featuredTitleText = (document.getElementById('featuredEventTitle')?.textContent || '')
        .replace(/\s+/g, ' ')
        .trim();

    const resolvedEventName = eventName || currentFeaturedEventName || featuredTitleText || 'Featured Event';

    // Update modal content
    document.getElementById('successTeamName').textContent = teamName || 'Your Team';
    document.getElementById('successEventName').textContent = resolvedEventName;
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
    const CONFETTI_COUNT = 100;
    const CLEAR_DELAY_MS = 5000;

    // Shape styles: [borderRadius, width]
    const shapeStyles = {
        circle: ['50%', null],
        square: [null, null],
        rectangle: [null, '6px']
    };
    const shapeNames = Object.keys(shapeStyles);

    for (let i = 0; i < CONFETTI_COUNT; i++) {
        const confetti = document.createElement('div');
        confetti.className = 'confetti';
        
        const shape = shapeNames[Math.floor(Math.random() * shapeNames.length)];
        const [borderRadius, width] = shapeStyles[shape];
        
        Object.assign(confetti.style, {
            left: `${Math.random() * 100}%`,
            backgroundColor: colors[Math.floor(Math.random() * colors.length)],
            animationDelay: `${Math.random() * 2}s`,
            animationDuration: `${Math.random() * 2 + 2}s`,
            ...(borderRadius && { borderRadius }),
            ...(width && { width })
        });

        container.appendChild(confetti);
    }

    setTimeout(() => { container.innerHTML = ''; }, CLEAR_DELAY_MS);
}

async function resolveSuccessEventName(activeEventCode) {
    if (currentFeaturedEventName) {
        return currentFeaturedEventName;
    }

    if (db && activeEventCode) {
        try {
            const eventDoc = await db.collection('events').doc(activeEventCode).get();
            if (eventDoc.exists && eventDoc.data()?.name) {
                return eventDoc.data().name;
            }
        } catch (err) {
            secureLog('[SuccessModal] Could not resolve event name from events collection');
        }
    }

    const fallbackNames = {
        testing: 'Testing (Sandbox)',
        promptquest: 'PromptQuest',
        uibattle: 'Quick Draw UI Battle',
        hackathon: 'Hackathon'
    };
    return fallbackNames[activeEventCode] || activeEventCode || 'Featured Event';
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

// ===== CUSTOM DROPDOWN (Lightswind-inspired) =====

function initCustomSelects() {
    document.querySelectorAll('.custom-select').forEach(function (dropdown) {
        var trigger = dropdown.querySelector('.select-trigger');
        var content = dropdown.querySelector('.select-content');
        if (!trigger || !content) return;

        // Toggle on trigger click
        trigger.addEventListener('click', function (e) {
            e.stopPropagation();
            var wasOpen = dropdown.classList.contains('open');
            // Close all other dropdowns first
            closeAllCustomSelects();
            if (!wasOpen) {
                dropdown.classList.add('open');
                trigger.setAttribute('aria-expanded', 'true');
            }
        });

        // Select item on click
        content.querySelectorAll('.select-item').forEach(function (item) {
            item.addEventListener('click', function (e) {
                e.stopPropagation();
                var value = item.dataset.value;
                var text = item.childNodes[0].textContent;

                // Update data-value on the dropdown container
                dropdown.dataset.value = value;

                // Update trigger display text
                var selectedText = trigger.querySelector('.selected-text');
                selectedText.textContent = text;
                selectedText.classList.remove('placeholder');

                // Update selected state on items
                content.querySelectorAll('.select-item').forEach(function (si) {
                    si.classList.remove('selected');
                });
                item.classList.add('selected');

                // Close dropdown
                dropdown.classList.remove('open');
                trigger.setAttribute('aria-expanded', 'false');
            });
        });

        // Keyboard support
        trigger.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') {
                dropdown.classList.remove('open');
                trigger.setAttribute('aria-expanded', 'false');
            } else if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                trigger.click();
            } else if (e.key === 'ArrowDown' && dropdown.classList.contains('open')) {
                e.preventDefault();
                var firstItem = content.querySelector('.select-item');
                if (firstItem) firstItem.focus();
            }
        });

        content.querySelectorAll('.select-item').forEach(function (item, idx, items) {
            item.setAttribute('tabindex', '0');
            item.addEventListener('keydown', function (e) {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    item.click();
                } else if (e.key === 'Escape') {
                    dropdown.classList.remove('open');
                    trigger.setAttribute('aria-expanded', 'false');
                    trigger.focus();
                } else if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    if (idx < items.length - 1) items[idx + 1].focus();
                } else if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    if (idx > 0) items[idx - 1].focus();
                    else trigger.focus();
                }
            });
        });
    });

    // Close on click outside
    document.addEventListener('mousedown', function (e) {
        if (!e.target.closest('.custom-select')) {
            closeAllCustomSelects();
        }
    });
}

function closeAllCustomSelects() {
    document.querySelectorAll('.custom-select.open').forEach(function (dropdown) {
        dropdown.classList.remove('open');
        var trigger = dropdown.querySelector('.select-trigger');
        if (trigger) trigger.setAttribute('aria-expanded', 'false');
    });
}

function resetAllCustomSelects() {
    document.querySelectorAll('.custom-select').forEach(function (dropdown) {
        dropdown.dataset.value = '';
        dropdown.classList.remove('open');
        var trigger = dropdown.querySelector('.select-trigger');
        if (trigger) {
            var selectedText = trigger.querySelector('.selected-text');
            // Determine placeholder text from context (Dept or Sem)
            var id = dropdown.id || '';
            selectedText.textContent = id.includes('Dept') ? 'Select Dept' : 'Select Sem';
            selectedText.classList.add('placeholder');
            trigger.setAttribute('aria-expanded', 'false');
        }
        dropdown.querySelectorAll('.select-item').forEach(function (item) {
            item.classList.remove('selected');
        });
    });
}

document.addEventListener('DOMContentLoaded', initCustomSelects);

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
    initWinnerPodium();
    initLightboxSwipe();
});

// ===== DUPLICATE CHECKS REMOVED =====
// Duplicate checking removed to keep Firestore read rules secure.
// Duplicates are handled on the admin side instead.

// ===== DYNAMIC WINNERS LOADING =====
async function loadWinners() {
    const winnersEmpty = document.getElementById('winnersEmpty');
    const winnerCards = [1, 2, 3].map(i => document.getElementById(`winner-${i}`));

    function showEmptyState() {
        winnersEmpty.style.display = 'block';
        hideSkeletonsShowWinners();
        winnerCards.forEach(card => { if (card) card.style.display = 'none'; });
    }

    function getMemberNames(winner) {
        return ['member1', 'member2', 'member3']
            .map(key => winner[key]?.name)
            .filter(Boolean);
    }

    try {
        secureLog('[Winners] Loading winners from Firestore...');

        const winnersSnapshot = await db.collection('registrations')
            .where('isWinner', '==', true)
            .get();

        if (winnersSnapshot.empty) {
            secureLog('[Winners] No winners found, showing empty state');
            showEmptyState();
            return;
        }

        // Filter and sort winners by position
        const winners = winnersSnapshot.docs
            .map(doc => ({ id: doc.id, ...doc.data() }))
            .filter(w => w.winnerPosition && w.winnerPosition <= 3)
            .sort((a, b) => a.winnerPosition - b.winnerPosition);

        winnersEmpty.style.display = 'none';

        winners.forEach(winner => {
            const position = winner.winnerPosition;
            const members = getMemberNames(winner);

            const nameEl = document.getElementById(`winner-${position}-name`);
            const membersEl = document.getElementById(`winner-${position}-members`);

            if (nameEl) {
                nameEl.textContent = winner.teamName || 'Winner';
            }
            if (membersEl) {
                // SECURITY: Use textContent or escapeHtml to prevent XSS from Firestore data
                membersEl.innerHTML = members.map(m => {
                    const div = document.createElement('div');
                    div.textContent = m;
                    return div.innerHTML;
                }).join('<br>');
            }

            secureLog(`[Winners] Loaded position ${position}: ${winner.teamName}`);
        });

        // Hide skeletons and show winner cards after loading
        hideSkeletonsShowWinners();

    } catch (err) {
        secureLog('[Winners] Error loading winners:', err);
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

// ===== DYNAMIC GALLERY LOADING =====
let galleryAllPhotos = [];
let currentGalleryEventFilter = 'all';

async function loadGallery() {
    const galleryScroll = document.getElementById('galleryScroll');
    const galleryLoading = document.getElementById('galleryLoading');
    const galleryEmpty = document.getElementById('galleryEmpty');
    const galleryFilters = document.getElementById('galleryFilters');

    if (!db || !galleryScroll) {
        secureLog('[Gallery] Firebase not initialized or gallery container missing');
        if (galleryLoading) galleryLoading.style.display = 'none';
        if (galleryEmpty) galleryEmpty.style.display = '';
        return;
    }

    try {
        secureLog('[Gallery] Loading gallery from Firestore...');
        const snapshot = await db.collection('gallery').get();

        galleryAllPhotos = snapshot.docs
            .map(doc => ({ id: doc.id, ...doc.data() }))
            .filter(p => p.isVisible === true)
            .sort((a, b) => (a.order || 0) - (b.order || 0));

        if (galleryLoading) galleryLoading.style.display = 'none';

        if (galleryAllPhotos.length === 0) {
            if (galleryEmpty) galleryEmpty.style.display = '';
            if (galleryFilters) galleryFilters.style.display = 'none';
            return;
        }

        // Build event filter chips
        const eventNames = [...new Set(galleryAllPhotos.map(p => p.eventName).filter(Boolean))];
        if (galleryFilters && eventNames.length > 1) {
            let chipsHtml = '<button class="gallery-filter-chip active" onclick="filterGallery(\'all\')">All</button>';
            eventNames.forEach(name => {
                chipsHtml += `<button class="gallery-filter-chip" onclick="filterGallery('${escapeHtml(name)}')">` +
                    `${escapeHtml(name)}</button>`;
            });
            galleryFilters.innerHTML = chipsHtml;
        } else if (galleryFilters) {
            galleryFilters.style.display = 'none';
        }

        renderGalleryItems(galleryAllPhotos);
        initGalleryReveal();

    } catch (error) {
        secureLog('[Gallery] Error loading gallery:', error);
        if (galleryLoading) galleryLoading.style.display = 'none';
        if (galleryEmpty) galleryEmpty.style.display = '';
    }
}

function renderGalleryItems(photos) {
    const galleryScroll = document.getElementById('galleryScroll');
    const galleryEmpty = document.getElementById('galleryEmpty');
    if (!galleryScroll) return;

    // Remove existing gallery items (keep loading/empty elements)
    galleryScroll.querySelectorAll('.gallery-item').forEach(el => el.remove());

    if (photos.length === 0) {
        if (galleryEmpty) galleryEmpty.style.display = '';
        return;
    }

    if (galleryEmpty) galleryEmpty.style.display = 'none';

    photos.forEach(photo => {
        const imagePath = photo.imageUrl
            ? (photo.imageUrl.startsWith('http') ? photo.imageUrl : photo.imageUrl)
            : '';
        const safeCaption = escapeHtml(photo.caption || '');

        const item = document.createElement('div');
        item.className = 'gallery-item';
        item.setAttribute('data-event', escapeHtml(photo.eventName || ''));
        item.onclick = function() { openImage(this); };
        item.innerHTML = `
            <img src="${escapeHtml(imagePath)}" alt="${safeCaption}" loading="lazy"
                 onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';" />
            <div style="width:100%;height:380px;display:none;align-items:center;justify-content:center;background:var(--bg-card);font-size:48px;color:var(--text-muted);">🖼️</div>
            <div class="gallery-overlay">
                <span>${safeCaption}</span>
            </div>`;

        // Insert before the empty state element
        galleryScroll.insertBefore(item, galleryEmpty);
    });
}

// Filter gallery by event
window.filterGallery = function(eventName) {
    currentGalleryEventFilter = eventName;

    // Update active chip
    document.querySelectorAll('.gallery-filter-chip').forEach(chip => {
        chip.classList.remove('active');
        const chipText = chip.textContent.trim();
        if ((eventName === 'all' && chipText === 'All') || chipText === eventName) {
            chip.classList.add('active');
        }
    });

    const filtered = eventName === 'all'
        ? galleryAllPhotos
        : galleryAllPhotos.filter(p => p.eventName === eventName);

    renderGalleryItems(filtered);
    initGalleryReveal();

    // Reset scroll to start
    const galleryScroll = document.getElementById('galleryScroll');
    if (galleryScroll) galleryScroll.scrollTo({ left: 0, behavior: 'smooth' });
};

// Load gallery on page load
document.addEventListener('DOMContentLoaded', function() {
    if (db) {
        setTimeout(loadGallery, 500);
    } else {
        const galleryLoading = document.getElementById('galleryLoading');
        const galleryEmpty = document.getElementById('galleryEmpty');
        if (galleryLoading) galleryLoading.style.display = 'none';
        if (galleryEmpty) galleryEmpty.style.display = '';
    }
});

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
    const formContainer = document.querySelector('.modal-body');

    // SECURITY: Execute reCAPTCHA v3 (invisible to user)
    let recaptchaToken = null;
    try {
        if (typeof grecaptcha !== 'undefined') {
            btn.disabled = true;
            btn.querySelector('.btn-text').textContent = 'Verifying...';

            recaptchaToken = await grecaptcha.execute(RECAPTCHA_SITE_KEY, { action: 'register' });
            secureLog('[Security] reCAPTCHA v3 token generated');

            btn.querySelector('.btn-text').textContent = 'Register Team 🚀';
            btn.disabled = false;
        }
    } catch (recaptchaError) {
        secureLog('[Security] reCAPTCHA failed, continuing:', recaptchaError);
        // Continue without reCAPTCHA if it fails (fallback to other protections)
    }

    const formData = {
        teamEmail: document.getElementById('teamEmail').value,
        teamName: document.getElementById('teamName').value,
        member1Name: document.getElementById('member1Name').value,
        member1USN: document.getElementById('member1USN').value,
        member1Dept: document.getElementById('member1Dept').dataset.value,
        member1Sem: document.getElementById('member1Sem').dataset.value,
        member2Name: document.getElementById('member2Name').value,
        member2USN: document.getElementById('member2USN').value,
        member2Dept: document.getElementById('member2Dept').dataset.value,
        member2Sem: document.getElementById('member2Sem').dataset.value,
        member3Name: document.getElementById('member3Name').value,
        member3USN: document.getElementById('member3USN').value,
        member3Dept: document.getElementById('member3Dept').dataset.value,
        member3Sem: document.getElementById('member3Sem').dataset.value
    };

    // ===== SECURITY: Process through security module =====
    if (window.ISTESecurity) {
        const result = window.ISTESecurity.processRegistration(formData, btn);

        // Handle rate limiting
        if (result.type === 'RATE_LIMITED') {
            window.ISTESecurity.showRateLimitError(formContainer, result.message);
            secureLog('[Security] Rate limit triggered:', result.message);
            return;
        }

        // Handle validation errors
        if (result.type === 'VALIDATION_ERROR') {
            window.ISTESecurity.displayValidationErrors(result.errors);
            secureLog('[Security] Validation failed:', result.errors);
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

    // Check if Firebase is initialized
    if (!db) {
        console.error('[App] Firebase not initialized. Cannot submit registration.');
        window.ISTESecurity.showRateLimitError(formContainer, 'Registration service unavailable. Please refresh the page.');
        ButtonDebouncer.restoreFromLoading(btn);
        return;
    }

    try {
        // SECURITY: Save sanitized data to Firestore
        // Dynamic routing: Read active event from config
        let activeEvent = 'testing'; // Default fallback
        try {
            let configDoc = await db.collection('config').doc('registration').get();

            // Backward-compat fallback for older admin saves.
            if (!configDoc.exists) {
                configDoc = await db.collection('config').doc('routing').get();
            }

            if (configDoc.exists && configDoc.data().activeEvent) {
                activeEvent = configDoc.data().activeEvent;
                secureLog('[Routing] Registering to event:', activeEvent);
            }
        } catch (configErr) {
            secureLog('[Routing] Using default event: testing');
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
        secureLog('[App] Registration successful for team:', formData.teamName);

        // Reset error count on successful registration
        if (window.ISTESecurity && window.ISTESecurity.registrationLimiter) {
            window.ISTESecurity.registrationLimiter.resetErrorCount();
        }

        // Count members (1 required + optional 2 and 3)
        const memberCount = 1 + [formData.member2Name, formData.member3Name].filter(Boolean).length;

        // Close registration modal and show success modal with confetti
        const successEventName = await resolveSuccessEventName(activeEvent);
        closeModal();
        setTimeout(() => {
            showSuccessModal(formData.teamName, successEventName, memberCount);
        }, 300);

    } catch (err) {
        secureLog('[App] Registration error:', err);

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
    if (typeof firebase === 'undefined' || typeof db === 'undefined') {
        secureLog('Firebase not initialized for team loading');
        // Show error message in all team grids
        ['faculty', 'core', 'volunteers'].forEach(category => {
            const grid = document.getElementById(`team-grid-${category}`);
            if (grid) {
                grid.innerHTML = '<p style="text-align: center; color: var(--text-muted); padding: 2rem;">Team data unavailable. Please check Firebase configuration.</p>';
            }
        });
        return;
    }
    
    try {
        // Use the global db instance already initialized at the top
        
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
        
        // Role class mapping - pattern-based lookup
        const ROLE_PATTERNS = [
            { keywords: ['president', 'hod', 'principal'], className: 'role-president' },
            { keywords: ['vice', 'coordinator'], className: 'role-vp' },
            { keywords: ['tech', 'developer'], className: 'role-tech' },
            { keywords: ['design', 'creative'], className: 'role-design' },
            { keywords: ['event', 'management'], className: 'role-event' },
            { keywords: ['social', 'media', 'content'], className: 'role-social' }
        ];

        function getRoleClass(role) {
            const roleLower = role.toLowerCase();
            const match = ROLE_PATTERNS.find(p => p.keywords.some(k => roleLower.includes(k)));
            return match?.className || 'role-tech';
        }
        
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
                // URL encode the path to handle spaces and special characters
                const imagePath = member.imageUrl 
                    ? (member.imageUrl.startsWith('http') 
                        ? member.imageUrl 
                        : `images/${encodeURIComponent(member.imageUrl)}`)
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
        secureLog('Error loading team members:', error);
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

// ===== FEATURED EVENT LOADER =====
// Load the featured event dynamically from Firestore
async function loadFeaturedEvent() {
    if (!db) {
        secureLog('[FeaturedEvent] Firebase not initialized');
        showNoFeaturedEvent();
        return;
    }
    
    try {
        // Query for the featured event
        const eventsRef = db.collection('events');
        const featuredQuery = eventsRef.where('isFeatured', '==', true).limit(1);
        const snapshot = await featuredQuery.get();
        
        if (snapshot.empty) {
            secureLog('[FeaturedEvent] No featured event found');
            showNoFeaturedEvent();
            return;
        }
        
        const eventData = snapshot.docs[0].data();
        secureLog('[FeaturedEvent] Loaded:', eventData.name);
        renderFeaturedEvent(eventData);
        
    } catch (error) {
        secureLog('[FeaturedEvent] Error loading:', error);
        showEventLoadError();
    }
}

// Render the featured event on the main page
function renderFeaturedEvent(event) {
    const titleEl = document.getElementById('featuredEventTitle');
    const detailsEl = document.getElementById('featuredEventDetails');
    const posterEl = document.getElementById('featuredEventPoster');
    const statusBadge = document.getElementById('eventStatusBadge');
    const registerBtn = document.getElementById('registerBtn');
    const contentEl = document.querySelector('.activity-content');
    const noEventEl = document.getElementById('noFeaturedEvent');
    
    // Show content, hide no-event state
    if (contentEl) contentEl.style.display = '';
    if (noEventEl) noEventEl.style.display = 'none';
    
    // Update title - handle both "Name - Subtitle" and simple names
    currentFeaturedEventName = event?.name || '';
    if (titleEl) {
        const nameParts = event.name.split(' - ');
        if (nameParts.length > 1) {
            titleEl.innerHTML = `${escapeHtml(nameParts[0])} - <span class="gradient-text">${escapeHtml(nameParts.slice(1).join(' - '))}</span>`;
        } else {
            titleEl.innerHTML = `<span class="gradient-text">${escapeHtml(event.name)}</span>`;
        }
    }
    
    // Update details
    if (detailsEl) {
        const teamSizeText = event.teamSize 
            ? (event.teamSize.min === event.teamSize.max 
                ? `${event.teamSize.min} Members` 
                : `${event.teamSize.min}-${event.teamSize.max} Members`)
            : 'Individual or Team';
        
        const dateDisplay = event.eventDate 
            ? `${event.eventDate}${event.eventDay ? ` (${event.eventDay})` : ''}`
            : 'Date TBA';
        
        detailsEl.innerHTML = `
            <div class="activity-detail">
                <div class="activity-detail-icon">📅</div>
                <span>${escapeHtml(dateDisplay)}</span>
            </div>
            <div class="activity-detail">
                <div class="activity-detail-icon">🕐</div>
                <span>${escapeHtml(event.eventTime || 'Time TBA')}</span>
            </div>
            <div class="activity-detail">
                <div class="activity-detail-icon">📍</div>
                <span>${escapeHtml(event.venue || 'Venue TBA')}</span>
            </div>
            <div class="activity-detail">
                <div class="activity-detail-icon">👥</div>
                <span>Team Size: ${escapeHtml(teamSizeText)}</span>
            </div>
        `;
    }
    
    // Update poster image
    if (posterEl && event.posterUrl) {
        posterEl.innerHTML = `<img src="${escapeHtml(event.posterUrl)}" alt="${escapeHtml(event.name)} Poster" loading="lazy" />`;
    } else if (posterEl) {
        // Show placeholder if no poster
        posterEl.innerHTML = `
            <div style="width: 100%; height: 400px; background: var(--gradient-soft); border-radius: 16px; display: flex; align-items: center; justify-content: center; flex-direction: column; gap: 12px;">
                <span style="font-size: 64px;">${event.emoji || '🎉'}</span>
                <span style="color: var(--text-muted); font-size: 14px;">Event Poster Coming Soon</span>
            </div>
        `;
    }
    
    // Update registration button status
    if (statusBadge && registerBtn) {
        const statusConfig = {
            'open': { class: 'open', text: '🟢 Open', btnEnabled: true, btnText: 'Register Now 🎉' },
            'closed': { class: 'closed', text: '🔴 Closed', btnEnabled: false, btnText: 'Registration Closed' },
            'coming_soon': { class: 'coming-soon', text: '🟡 Coming Soon', btnEnabled: false, btnText: 'Coming Soon' }
        };
        
        const status = statusConfig[event.registrationStatus] || statusConfig['open'];
        statusBadge.className = `event-status-badge ${status.class}`;
        statusBadge.textContent = status.text;
        registerBtn.disabled = !status.btnEnabled;
        registerBtn.textContent = status.btnText;
    }
}

// Show "no featured event" state
function showNoFeaturedEvent() {
    currentFeaturedEventName = '';
    const contentEl = document.querySelector('.activity-content');
    const noEventEl = document.getElementById('noFeaturedEvent');
    
    if (contentEl) contentEl.style.display = 'none';
    if (noEventEl) noEventEl.style.display = 'flex';
}

// Show error state
function showEventLoadError() {
    const titleEl = document.getElementById('featuredEventTitle');
    const detailsEl = document.getElementById('featuredEventDetails');
    const registerBtn = document.getElementById('registerBtn');
    const statusBadge = document.getElementById('eventStatusBadge');
    
    if (titleEl) titleEl.textContent = 'Unable to Load Event';
    if (detailsEl) detailsEl.innerHTML = '<p style="color: var(--text-muted);">Please refresh the page or check back later.</p>';
    if (registerBtn) {
        registerBtn.disabled = true;
        registerBtn.textContent = 'Unavailable';
    }
    if (statusBadge) {
        statusBadge.className = 'event-status-badge';
        statusBadge.textContent = '⚠️ Error';
    }
}

// Simple HTML escape for security
function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

// Load featured event when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    if (db) {
        loadFeaturedEvent();
    }
});

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
                secureLog('Error submitting feedback:', error);
                submitBtn.disabled = false;
                submitBtn.textContent = 'Try Again';
            }
        });
    }
});

