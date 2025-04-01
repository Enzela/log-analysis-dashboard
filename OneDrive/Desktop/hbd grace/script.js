document.body.addEventListener("click", function () {
    const nextPage = document.body.getAttribute("data-next");
    if (nextPage) {
        window.location.href = nextPage;
    }
});
