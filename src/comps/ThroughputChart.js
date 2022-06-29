import { Card, CardHeader, Divider } from "@mui/material";
import { Line } from "react-chartjs-2";
import React from "react";

const ThroughputCard = ({ data }) => {
    

    return (
        <Card>
            <CardHeader title="Traffic by Device" />
            <Line data = {data} /> 
        </Card>
    )

}

export default ThroughputCard;