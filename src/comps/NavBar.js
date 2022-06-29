import React, { useState } from 'react';
import { Nav } from 'react-bootstrap';



const NavBar = () => {

  const [navbarOpen, setNavbarOpen] = useState(false);


  const handleToggle = () => {
    setNavbarOpen(prev => !prev)
  }

  return (
    <nav className='navBar'>
      <button onClick={handleToggle}>
        {navbarOpen ? "Close" : "Open"}
      </button>
      <ul className={`menuNav ${navbarOpen ? " showMenu" : ""}`}>
      </ul>
    </nav>
  
  )


}

export default NavBar