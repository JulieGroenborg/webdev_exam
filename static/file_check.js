document.querySelectorAll('input[type="file"]').forEach(input => {
    input.addEventListener('change', function () {
        const file = this.files[0];
        if (file) {
            const allowedExtensions = ['image/jpeg', 'image/png', 'image/jpg'];
            const maxSize = 2 * 1024 * 1024; // 2 MB

            if (!allowedExtensions.includes(file.type)) {
                alert('Only JPG and PNG files are allowed.');
                this.value = ''; // Reset the input
            } else if (file.size > maxSize) {
                alert('File size must be less than 2 MB.');
                this.value = ''; // Reset the input
            }
        }
    });
});
