// Dummy accounts for validation
const accounts = [
    { email: "example@berkeley.edu", password: "123456" },
    { email: "james@berkeley.edu", password: "password123" },
];

// Select form element
const form = document.getElementById("signInForm");

// Handle form submission
form.addEventListener("submit", function (event) {
    event.preventDefault(); // Prevent form submission

    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    // Check if account exists
    const accountExists = accounts.some(
        (account) => account.email === email && account.password === password
    );

    if (!accountExists) {
        // Open a new window with the error message
        window.open(
            "error.html",
            "_blank",
            "width=400,height=200,top=200,left=500"
        );
    } else {
        // Redirect to dashboard or home page on success
        window.location.href = "mainPage.html";
    }
});
