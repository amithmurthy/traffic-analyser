import Plot from "react-plotlyjs"




const LineChart = ({data, layout}) => {
    
    return(
        <Plot
        data={data}
        layout={layout}
        config={{responsive: true}}
        style={{width: "100%", height:"100%"}}
        />
    );
};


export default LineChart
