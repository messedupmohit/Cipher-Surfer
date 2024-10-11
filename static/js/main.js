// main.js

// Function to validate password and confirm password fields
function validatePassword() {
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm_password').value;

    if (password !== confirmPassword) {
        document.getElementById('passwordError').innerText = "Passwords do not match.";
        return false;
    }
    document.getElementById('passwordError').innerText = "";  // Clear any previous error
    return true;
}

// Attach event listener to the encryption form
document.addEventListener('DOMContentLoaded', function () {
    const encryptForm = document.querySelector('form[action^="/encrypt"]');

    if (encryptForm) {
        encryptForm.addEventListener('submit', function (event) {
            if (!validatePassword()) {
                event.preventDefault();  // Prevent form submission if passwords do not match
            }
        });
    }
});

// jQuery for smoother transitions and effects (requires jQuery to be loaded)
$(document).ready(function () {
    // Smooth scroll for navigation links
    $('.navigation-item a').on('click', function (event) {
        if (this.hash !== "") {
            event.preventDefault();
            const hash = this.hash;
            $('html, body').animate({
                scrollTop: $(hash).offset().top
            }, 800, function () {
                window.location.hash = hash;
            });
        }
    });

    // Highlight the current section in the navigation bar
    $(window).on('scroll', function () {
        const scrollPos = $(document).scrollTop();
        $('.navigation-item a').each(function () {
            const currLink = $(this);
            const refElement = $(currLink.attr('href'));
            if (refElement.position().top <= scrollPos && refElement.position().top + refElement.height() > scrollPos) {
                $('.navigation-item a').removeClass('active');
                currLink.addClass('active');
            } else {
                currLink.removeClass('active');
            }
        });
    });
});
