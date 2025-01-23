const mobileMenu = document.getElementById("mobile-menu");
const navbarMenu = document.querySelector(".navbar-menu");
const navbarRight = document.querySelector(".navbar-right");
const logoutButton = navbarRight.querySelector(".btn-logout");

mobileMenu.addEventListener("click", () => {
  console.log("clicked");
  navbarMenu.classList.toggle("active"); //active
});

if(window.innerWidth <= 768){
  if(!navbarMenu.contains(logoutButton)){
    navbarMenu.appendChild(logoutButton);
  }
  else
  {
    if(!navbarRight.contains(logoutButton)){
      navbarRight.appendChild(logoutButton);
    }
  }
}


window.addEventListener("resize", () => { //resize event listener that knows when to add logout button to navbar-right when screen is full again
  if (window.innerWidth > 768) {
    // Restore logout button to navbar-right in desktop view
    if (!navbarRight.contains(logoutButton)) {
      navbarRight.appendChild(logoutButton);
    }
  }
});