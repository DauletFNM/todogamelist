    gsap.from(".login-card", { 
  rotation: 360,
  duration: 2,
  repeat: -1,
  repeatDelay: 10,
  ease: 'bounce.out'
    });
      gsap.from("input, button, .login-card a", {
      duration: 0.8,
      y: 20,
      opacity: 0,
      delay: 0.3,
      stagger: 0.1
    });
    gsap.to(".box", { 
  duration: 2,
  x: "15vw",
  rotation: 360,
});


