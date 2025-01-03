// Handle progress bar updates
document.querySelectorAll('input[type="range"]').forEach(range => {
    range.addEventListener('input', (e) => {
        const progress = e.target.value;
        const form = e.target.closest('form');
        const button = form.querySelector('button');
        button.textContent = `Update Progress (${progress}%)`;
    });
});

// Add confirmation before deleting entries
document.querySelectorAll('.delete-entry').forEach(button => {
    button.addEventListener('click', (e) => {
        if (!confirm('Are you sure you want to delete this entry?')) {
            e.preventDefault();
        }
    });
});

// Auto-expand textareas
document.querySelectorAll('textarea').forEach(textarea => {
    textarea.addEventListener('input', function() {
        this.style.height = 'auto';
        this.style.height = this.scrollHeight + 'px';
    });
});