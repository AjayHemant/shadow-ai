document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('escape-btn').addEventListener('click', () => {
        // Because Chrome saves the blocked search in history, going back 1 page 
        // just triggers the block again! We must go back 2 pages or to a safe default.
        if (window.history.length > 2) {
            window.history.go(-2);
        } else {
            window.location.href = 'https://www.google.com';
        }
    });
});
