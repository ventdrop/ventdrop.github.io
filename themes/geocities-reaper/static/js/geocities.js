// GeoCities Reaper Theme - Authentic 90s Web Experience JavaScript
// Bringing back the glory days of the early web!

(function() {
  'use strict';

  // Visitor Counter Animation
  function animateVisitorCounter() {
    const counter = document.getElementById('visitor-count');
    const totalHits = document.getElementById('total-hits');
    const onlineNow = document.getElementById('online-now');
    
    if (counter) {
      // Generate random visitor count between 1000-9999
      const baseCount = Math.floor(Math.random() * 8999) + 1000;
      let currentCount = 0;
      
      const interval = setInterval(() => {
        currentCount += Math.floor(Math.random() * 50) + 1;
        if (currentCount >= baseCount) {
          currentCount = baseCount;
          clearInterval(interval);
        }
        counter.textContent = String(currentCount).padStart(6, '0');
      }, 50);
    }
    
    if (totalHits) {
      totalHits.textContent = Math.floor(Math.random() * 50000) + 10000;
    }
    
    if (onlineNow) {
      // Random number of online users
      onlineNow.textContent = Math.floor(Math.random() * 100) + 1;
      
      // Update online count every 30 seconds
      setInterval(() => {
        const variance = Math.floor(Math.random() * 10) - 5;
        const current = parseInt(onlineNow.textContent) + variance;
        onlineNow.textContent = Math.max(1, Math.min(150, current));
      }, 30000);
    }
  }

  // Random 90s Quotes
  const ninetiesToQuotes = [
    "The information superhighway is here!",
    "Welcome to my corner of cyberspace!",
    "Surf's up on the World Wide Web!",
    "This page best viewed with Netscape!",
    "Enter the digital frontier!",
    "Connecting minds across the globe!",
    "The future is now!",
    "Cyberpunk dreams made real!",
    "Information wants to be free!",
    "Digital revolution in progress!"
  ];

  function randomizeQuote() {
    const quoteElement = document.querySelector('.quote-text');
    if (quoteElement && !quoteElement.dataset.original) {
      // Store original quote
      quoteElement.dataset.original = quoteElement.textContent;
      
      // 10% chance to show random 90s quote
      if (Math.random() < 0.1) {
        const randomQuote = ninetiesToQuotes[Math.floor(Math.random() * ninetiesToQuotes.length)];
        quoteElement.textContent = `"${randomQuote}"`;
        
        const authorElement = document.querySelector('.quote-author');
        if (authorElement) {
          authorElement.textContent = "- The Digital Oracle";
        }
      }
    }
  }

  // Retro Sound Effects (using Web Audio API)
  function createRetroSounds() {
    const audioContext = new (window.AudioContext || window.webkitAudioContext)();
    
    function playBeep(frequency = 800, duration = 200) {
      const oscillator = audioContext.createOscillator();
      const gainNode = audioContext.createGain();
      
      oscillator.connect(gainNode);
      gainNode.connect(audioContext.destination);
      
      oscillator.frequency.value = frequency;
      oscillator.type = 'square';
      
      gainNode.gain.setValueAtTime(0.1, audioContext.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + duration / 1000);
      
      oscillator.start(audioContext.currentTime);
      oscillator.stop(audioContext.currentTime + duration / 1000);
    }
    
    // Add sound effects to links
    document.querySelectorAll('a').forEach(link => {
      link.addEventListener('mouseenter', () => {
        if (Math.random() < 0.3) { // 30% chance
          playBeep(600 + Math.random() * 400, 100);
        }
      });
    });
    
    // Add sound to navigation
    document.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', () => {
        playBeep(1000, 150);
      });
    });
  }

  // Retro Mouse Trail Effect
  function createMouseTrail() {
    const trail = [];
    const trailLength = 8;
    
    function createTrailElement() {
      const element = document.createElement('div');
      element.style.position = 'fixed';
      element.style.width = '8px';
      element.style.height = '8px';
      element.style.backgroundColor = '#ff00ff';
      element.style.borderRadius = '50%';
      element.style.pointerEvents = 'none';
      element.style.zIndex = '9999';
      element.style.transition = 'opacity 0.5s';
      document.body.appendChild(element);
      return element;
    }
    
    document.addEventListener('mousemove', (e) => {
      // Only show trail 20% of the time to avoid overdoing it
      if (Math.random() < 0.2) {
        const trailElement = createTrailElement();
        trailElement.style.left = e.clientX + 'px';
        trailElement.style.top = e.clientY + 'px';
        
        // Fade out and remove
        setTimeout(() => {
          trailElement.style.opacity = '0';
          setTimeout(() => {
            if (trailElement.parentNode) {
              trailElement.parentNode.removeChild(trailElement);
            }
          }, 500);
        }, 100);
      }
    });
  }

  // Random Background Color Shifts
  function randomBackgroundShifts() {
    const container = document.querySelector('.container');
    if (!container) return;
    
    setInterval(() => {
      if (Math.random() < 0.1) { // 10% chance every interval
        const colors = ['#ff00ff', '#00ffff', '#ffff00', '#ff0000', '#00ff00', '#0080ff'];
        const randomColor = colors[Math.floor(Math.random() * colors.length)];
        container.style.borderColor = randomColor;
        container.style.boxShadow = `0 0 20px ${randomColor}80`;
        
        // Reset after 2 seconds
        setTimeout(() => {
          container.style.borderColor = '#ff00ff';
          container.style.boxShadow = '0 0 20px rgba(255, 0, 255, 0.8)';
        }, 2000);
      }
    }, 5000);
  }

  // Retro Loading Messages
  function showLoadingMessages() {
    const messages = [
      "Loading awesome content...",
      "Connecting to cyberspace...",
      "Initializing web experience...",
      "Downloading the future...",
      "Establishing data link...",
      "Activating retro mode..."
    ];
    
    // Show loading message briefly on page load
    const loadingDiv = document.createElement('div');
    loadingDiv.style.cssText = `
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      background: #000080;
      color: #ffff00;
      padding: 20px;
      border: 3px ridge #c0c0c0;
      font-family: 'Courier Prime', monospace;
      z-index: 10000;
      text-align: center;
      box-shadow: 0 0 20px rgba(0, 0, 255, 0.8);
    `;
    
    const message = messages[Math.floor(Math.random() * messages.length)];
    loadingDiv.innerHTML = `
      <div style="font-size: 1.2rem; margin-bottom: 10px;">${message}</div>
      <div style="color: #00ff00;">█████████░ 90%</div>
    `;
    
    document.body.appendChild(loadingDiv);
    
    setTimeout(() => {
      loadingDiv.style.opacity = '0';
      loadingDiv.style.transition = 'opacity 0.5s';
      setTimeout(() => {
        if (loadingDiv.parentNode) {
          loadingDiv.parentNode.removeChild(loadingDiv);
        }
      }, 500);
    }, 1500);
  }

    document.addEventListener('DOMContentLoaded', function() {
    // Find all buttons with the class 'share-copy'
    const copyButtons = document.querySelectorAll('.share-copy');

    copyButtons.forEach(button => {
        button.addEventListener('click', function(event) {
        // Get the URL from the data-url attribute of the clicked button
        const urlToCopy = this.dataset.url;

        // Use the modern Clipboard API to copy the text
        if (navigator.clipboard) {
            navigator.clipboard.writeText(urlToCopy).then(() => {
            // Optional: Provide user feedback
            const originalText = button.innerHTML;
            button.innerHTML = '✅ Copied!';
            setTimeout(() => {
                button.innerHTML = originalText;
            }, 2000);
            }).catch(err => {
            console.error('Failed to copy text: ', err);
            });
        } else {
            // Fallback for older browsers
            console.warn('Clipboard API not supported.');
            fallbackCopyToClipboard(urlToCopy);
        }
        });
    });
    });

  // Toggle Music Function (for future MIDI support)
  window.toggleMusic = function() {
    const player = document.querySelector('.midi-player');
    const isPlaying = player.dataset.playing === 'true';
    
    if (isPlaying) {
      player.dataset.playing = 'false';
      document.querySelector('#song-title').textContent = 'MIDI_SONG.MID (Paused)';
    } else {
      player.dataset.playing = 'true';
      document.querySelector('#song-title').textContent = 'MIDI_SONG.MID (Playing)';
    }
    
    // Show retro notification
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      bottom: 20px;
      left: 20px;
      background: #000080;
      color: #ffff00;
      padding: 10px 15px;
      border: 2px solid #ffff00;
      font-family: 'Courier Prime', monospace;
      z-index: 10000;
      animation: blink 0.5s linear 3;
    `;
    notification.textContent = isPlaying ? '🔇 Music Paused' : '🎵 Music Playing';
    document.body.appendChild(notification);
    
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, 2000);
  };

  // Easter Eggs
  function initializeEasterEggs() {
    let konamiCode = [];
    const konamiSequence = [
      'ArrowUp', 'ArrowUp', 'ArrowDown', 'ArrowDown',
      'ArrowLeft', 'ArrowRight', 'ArrowLeft', 'ArrowRight',
      'KeyB', 'KeyA'
    ];
    
    document.addEventListener('keydown', (e) => {
      konamiCode.push(e.code);
      if (konamiCode.length > konamiSequence.length) {
        konamiCode.shift();
      }
      
      if (konamiCode.join(',') === konamiSequence.join(',')) {
        activateKonamiMode();
        konamiCode = [];
      }
    });
    
    // Secret click sequence on title
    let titleClicks = 0;
    const siteTitle = document.querySelector('.site-title');
    if (siteTitle) {
      siteTitle.addEventListener('click', () => {
        titleClicks++;
        if (titleClicks === 5) {
          activateHyperMode();
          titleClicks = 0;
        }
        
        // Reset counter after 3 seconds
        setTimeout(() => {
          if (titleClicks > 0) titleClicks--;
        }, 3000);
      });
    }
  }

  function activateKonamiMode() {
    document.body.style.animation = 'rainbow-spin 2s linear infinite';
    document.body.style.transformOrigin = 'center';
    
    // Add rainbow spin keyframe
    if (!document.getElementById('konami-style')) {
      const style = document.createElement('style');
      style.id = 'konami-style';
      style.textContent = `
        @keyframes rainbow-spin {
          0% { transform: rotate(0deg) hue-rotate(0deg); }
          100% { transform: rotate(360deg) hue-rotate(360deg); }
        }
      `;
      document.head.appendChild(style);
    }
    
    // Show congratulations message
    const congrats = document.createElement('div');
    congrats.style.cssText = `
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      background: linear-gradient(45deg, #ff0000, #ff8000, #ffff00, #00ff00, #0080ff, #8000ff);
      color: #fff;
      padding: 30px;
      border: 5px ridge #fff;
      font-size: 2rem;
      font-weight: bold;
      text-align: center;
      z-index: 10001;
      text-shadow: 3px 3px 0px #000;
      animation: blink 0.5s linear infinite;
    `;
    congrats.innerHTML = '🎉 KONAMI CODE ACTIVATED! 🎉<br>Welcome to the 90s Matrix!';
    document.body.appendChild(congrats);
    
    setTimeout(() => {
      document.body.style.animation = '';
      if (congrats.parentNode) {
        congrats.parentNode.removeChild(congrats);
      }
    }, 5000);
  }

  function activateHyperMode() {
    // Add Matrix-style falling characters
    const matrixContainer = document.createElement('div');
    matrixContainer.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      pointer-events: none;
      z-index: 9998;
      overflow: hidden;
    `;
    
    const characters = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
    
    for (let i = 0; i < 20; i++) {
      const column = document.createElement('div');
      column.style.cssText = `
        position: absolute;
        top: -100%;
        left: ${Math.random() * 100}%;
        color: #00ff00;
        font-family: 'Courier Prime', monospace;
        font-size: 14px;
        animation: matrix-fall ${3 + Math.random() * 2}s linear infinite;
        animation-delay: ${Math.random() * 2}s;
      `;
      
      let columnText = '';
      for (let j = 0; j < 20; j++) {
        columnText += characters[Math.floor(Math.random() * characters.length)] + '<br>';
      }
      column.innerHTML = columnText;
      matrixContainer.appendChild(column);
    }
    
    // Add keyframe for matrix effect
    if (!document.getElementById('matrix-style')) {
      const style = document.createElement('style');
      style.id = 'matrix-style';
      style.textContent = `
        @keyframes matrix-fall {
          0% { top: -100%; opacity: 1; }
          100% { top: 100%; opacity: 0; }
        }
      `;
      document.head.appendChild(style);
    }
    
    document.body.appendChild(matrixContainer);
    
    // Show hyper mode message
    const hyperMsg = document.createElement('div');
    hyperMsg.style.cssText = `
      position: fixed;
      top: 20%;
      left: 50%;
      transform: translateX(-50%);
      background: #000;
      color: #00ff00;
      padding: 20px;
      border: 3px solid #00ff00;
      font-family: 'Courier Prime', monospace;
      z-index: 10001;
      text-align: center;
      box-shadow: 0 0 20px #00ff00;
    `;
    hyperMsg.innerHTML = '🚀 HYPER MODE ACTIVATED! 🚀<br>Welcome to Cyberspace!';
    document.body.appendChild(hyperMsg);
    
    setTimeout(() => {
      if (matrixContainer.parentNode) {
        matrixContainer.parentNode.removeChild(matrixContainer);
      }
      if (hyperMsg.parentNode) {
        hyperMsg.parentNode.removeChild(hyperMsg);
      }
    }, 10000);
  }

  // Random 90s Status Messages
  function showRandomStatusMessages() {
    const messages = [
      "📡 Downloading new GIFs...",
      "💾 Defragmenting hard drive...",
      "🔍 Searching AltaVista...",
      "📞 Connecting via 56k modem...",
      "💿 Loading CD-ROM...",
      "🖨️ Printing banners...",
      "📧 Checking AOL mail...",
      "🎮 Calibrating joystick...",
      "📼 Rewinding VHS...",
      "💻 Updating Windows 98..."
    ];
    
    function showMessage() {
      if (Math.random() < 0.3) { // 30% chance
        const message = messages[Math.floor(Math.random() * messages.length)];
        const statusDiv = document.createElement('div');
        statusDiv.style.cssText = `
          position: fixed;
          bottom: 20px;
          right: 20px;
          background: #c0c0c0;
          border: 2px outset #c0c0c0;
          padding: 8px 12px;
          font-family: 'Courier Prime', monospace;
          font-size: 0.8rem;
          z-index: 9999;
          max-width: 200px;
        `;
        statusDiv.textContent = message;
        document.body.appendChild(statusDiv);
        
        setTimeout(() => {
          statusDiv.style.opacity = '0';
          statusDiv.style.transition = 'opacity 0.5s';
          setTimeout(() => {
            if (statusDiv.parentNode) {
              statusDiv.parentNode.removeChild(statusDiv);
            }
          }, 500);
        }, 3000);
      }
    }
    
    // Show random messages every 30-60 seconds
    setInterval(showMessage, 30000 + Math.random() * 30000);
  }

  // Add floating "NEW!" badges randomly
  function addFloatingBadges() {
    const badges = ['NEW!', 'HOT!', 'COOL!', 'WOW!', 'RAD!'];
    
    function createFloatingBadge() {
      if (Math.random() < 0.1) { // 10% chance
        const badge = document.createElement('div');
        badge.style.cssText = `
          position: fixed;
          right: -100px;
          top: ${Math.random() * 60 + 20}%;
          background: #ff0000;
          color: #ffff00;
          padding: 5px 10px;
          border: 2px solid #ffff00;
          font-weight: bold;
          font-size: 0.8rem;
          z-index: 9999;
          animation: float-across 8s linear;
        `;
        
        badge.textContent = badges[Math.floor(Math.random() * badges.length)];
        
        if (!document.getElementById('float-style')) {
          const style = document.createElement('style');
          style.id = 'float-style';
          style.textContent = `
            @keyframes float-across {
              0% { right: -100px; opacity: 1; }
              10% { opacity: 1; }
              90% { opacity: 1; }
              100% { right: 100%; opacity: 0; }
            }
          `;
          document.head.appendChild(style);
        }
        
        document.body.appendChild(badge);
        
        setTimeout(() => {
          if (badge.parentNode) {
            badge.parentNode.removeChild(badge);
          }
        }, 8000);
      }
    }
    
    // Create floating badges every 45-90 seconds
    setInterval(createFloatingBadge, 45000 + Math.random() * 45000);
  }

  // Initialize all features when page loads
  document.addEventListener('DOMContentLoaded', () => {
    // Core features
    animateVisitorCounter();
    randomizeQuote();
    
    // Only enable sound effects if user interacts first (browser requirement)
    let soundsEnabled = false;
    document.addEventListener('click', () => {
      if (!soundsEnabled) {
        createRetroSounds();
        soundsEnabled = true;
      }
    }, { once: true });
    
    // Visual effects
    createMouseTrail();
    randomBackgroundShifts();
    initializeEasterEggs();
    
    // Periodic effects
    setTimeout(showRandomStatusMessages, 10000); // Start after 10 seconds
    setTimeout(addFloatingBadges, 30000); // Start after 30 seconds
    
    // Show loading message
    if (document.readyState === 'loading') {
      showLoadingMessages();
    }
    
    // Add retro scrollbar styling
    const style = document.createElement('style');
    style.textContent = `
      ::-webkit-scrollbar {
        width: 16px;
      }
      ::-webkit-scrollbar-track {
        background: #c0c0c0;
        border: 2px inset #c0c0c0;
      }
      ::-webkit-scrollbar-thumb {
        background: #808080;
        border: 2px outset #808080;
      }
      ::-webkit-scrollbar-thumb:hover {
        background: #606060;
      }
    `;
    document.head.appendChild(style);
  });

  // Add some fun console messages for developers
  console.log("%c🌟 Welcome to GeoCities Reaper! 🌟", 
              "background: linear-gradient(45deg, #ff0000, #ff8000, #ffff00, #00ff00, #0080ff, #8000ff); color: white; padding: 10px; font-size: 16px; font-weight: bold;");
  console.log("%cThis site is powered by pure 90s nostalgia!", 
              "color: #ff00ff; font-size: 14px; font-weight: bold;");
  console.log("%cTry the Konami Code: ↑↑↓↓←→←→BA", 
              "color: #00ff00; font-family: 'Courier New', monospace;");
  console.log("%cOr click the site title 5 times for a surprise!", 
              "color: #0080ff; font-style: italic;");

})();