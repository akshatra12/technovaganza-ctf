// Global socket connection
const socket = io();

// Common utility functions
const utils = {
    showNotification: function(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} alert-dismissible fade show`;
        notification.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        // Add to page
        const container = document.querySelector('.container');
        container.insertBefore(notification, container.firstChild);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);
    },

    formatTime: function(seconds) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    },

    debounce: function(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
};

// Leaderboard functionality
const leaderboard = {
    init: function() {
        this.socket = io();
        this.bindEvents();
    },

    bindEvents: function() {
        this.socket.on('leaderboard_update', (data) => {
            this.refreshLeaderboard();
        });

        this.socket.on('leaderboard_data', (data) => {
            this.updateTable(data.leaderboard);
        });
    },

    refreshLeaderboard: function() {
        this.socket.emit('request_leaderboard');
    },

    updateTable: function(leaderboardData) {
        const tbody = document.getElementById('leaderboard-body');
        if (!tbody) return;

        tbody.innerHTML = '';

        leaderboardData.forEach((entry, index) => {
            const row = document.createElement('tr');
            
            // Add highlight animation for updates
            row.className = 'leaderboard-update';
            
            row.innerHTML = `
                <td>${index + 1}</td>
                <td>${entry.teamname}</td>
                <td><strong>${entry.score}</strong></td>
            `;
            
            tbody.appendChild(row);
        });
    }
};

// Challenge submission handling
const challengeHandler = {
    init: function() {
        this.bindFormSubmit();
    },

    bindFormSubmit: function() {
        const forms = document.querySelectorAll('#flag-form');
        forms.forEach(form => {
            form.addEventListener('submit', this.handleFlagSubmission.bind(this));
        });
    },

    handleFlagSubmission: function(e) {
        e.preventDefault();
        
        const form = e.target;
        const flagInput = form.querySelector('#flag-input');
        const resultDiv = form.parentElement.querySelector('#result-message');
        const challengeId = form.getAttribute('data-challenge-id') || 
                           window.location.pathname.split('/').pop();

        if (!flagInput.value.trim()) {
            this.showResult(resultDiv, 'Please enter a flag', 'danger');
            return;
        }

        this.submitFlag(challengeId, flagInput.value, resultDiv)
            .then(data => {
                if (data.success) {
                    this.showResult(resultDiv, data.message, 'success');
                    flagInput.value = '';
                    // Refresh page after success
                    setTimeout(() => location.reload(), 2000);
                } else {
                    this.showResult(resultDiv, data.message, 'danger');
                    if (data.message.includes('Banned')) {
                        setTimeout(() => window.location.href = '/banned', 2000);
                    } else if (data.message.includes('attempts')) {
                        setTimeout(() => location.reload(), 2000);
                    }
                }
            })
            .catch(error => {
                this.showResult(resultDiv, 'Error submitting flag', 'danger');
            });
    },

    submitFlag: async function(challengeId, flag, resultDiv) {
        const response = await fetch(`/submit_flag/${challengeId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `flag=${encodeURIComponent(flag)}`
        });
        return await response.json();
    },

    showResult: function(container, message, type) {
        container.innerHTML = `
            <div class="alert alert-${type} alert-dismissible fade show">
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;
    }
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize leaderboard if on relevant page
    if (document.getElementById('leaderboard-body')) {
        leaderboard.init();
    }

    // Initialize challenge handler if on challenge page
    if (document.getElementById('flag-form')) {
        challengeHandler.init();
    }

    // Auto-refresh leaderboard every 30 seconds
    if (window.location.pathname === '/leaderboard') {
        setInterval(() => {
            leaderboard.refreshLeaderboard();
        }, 30000);
    }
});