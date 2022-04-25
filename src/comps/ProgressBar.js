import React from "react";

const ProgressBar = (props) => {
    const {bgcolor, completedPercentage} = props;
    
    const containerStyles = {
        height: 20,
        width: '100%',
        backgroundColor: "#e0e0de",
        borderRadius: 50,
        margin: 50
    }
    
    const fillerStyles = {
        height: '100%',
        width: `${completedPercentage}%`,
        backgroundColor: bgcolor,
        borderRadius: 'inherit',
        transition:'width 1s ease-in-out',
        textAlign: 'right'
    }
    
    const labelStyles = {
        padding:5,
        color:'white',
        fontWeight: 'bold'
    }
     
    return(
        <div style={containerStyles}>
            <div style={fillerStyles}>
                <span style={labelStyles}>{`${completedPercentage}%`} </span>
            </div>
        </div>
    )
};

export default ProgressBar;