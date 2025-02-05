// Handle the search form submission
document.querySelector(".search-form").addEventListener("submit", (event) => {
    event.preventDefault();

    const name = document.getElementById("search-name").value.trim();
    const major = document.getElementById("search-major").value.trim();

    if (name || major) {
        alert(`Searching for participants with name: ${name || 'Any'} and major: ${major || 'Any'}`);
    } else {
        alert("Please enter a name or a major to search!");
    }
});
