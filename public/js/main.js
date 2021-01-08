// Sidebar
let mediaQueryPhone = window.matchMedia('(max-width: 480px)');
let mediaQueryTab = window.matchMedia('(max-width: 768px)');
let mediaQueryBigTab = window.matchMedia('(max-width: 1024px)');

mediaQueryPhone.addListener(sidebarHandler);
mediaQueryTab.addListener(sidebarHandler);
mediaQueryBigTab.addListener(sidebarHandler);

function sidebarHandler() {
    let sidebar = document.getElementById('sidebar');
    let content = document.getElementsByClassName('content')[0];

    if (sidebar.style.width == '0rem') {
        if (mediaQueryPhone.matches) {
            sidebar.style.width = '100vw';
            content.style.marginLeft = '100vw';
        } 
        else if (mediaQueryTab.matches) {
            sidebar.style.width = '40vw';
            content.style.marginLeft = '40vw';
        }
        else if (mediaQueryBigTab.matches) {
            sidebar.style.width = '30vw';
            content.style.marginLeft = '30vw';
        }
        else {
            sidebar.style.width = '20vw';
            content.style.marginLeft = '20vw';
        }
    } else {
        sidebar.style.width = '0rem';
        content.style.marginLeft = '0rem';
    }
}
