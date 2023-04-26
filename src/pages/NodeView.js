import ThroughputCard from "../comps/ThroughputChart"
import { useParams } from "react-router-dom"
import Sidebar from "../comps/Sidebar";
import Plot from "react-plotly.js"
import { useEffect, useState } from "react";


const NodeView = () => {
    let params = useParams();
    const [inputTime, setInputTime] = useState([])
    const [inputPktRate, setInputPktRate] = useState([])
    const [inputByteRate, setInputByteRate] = useState([])
    const [outputTime, setOutputTime] = useState([])
    const [outputPktRate, setOutputPktRate] = useState([])
    const [outputByteRate, setOutputByteRate] = useState([])
    const [showPlot, setShowPlot] = useState(false)

    const request = {'getNodeView': params?.nodeId}
    console.log('node view rendered')

    if(!showPlot){
        window.electron.facadeAPI.sendRequest(request)
        window.electron.handle('getNodeView', (event,data) => function(event,data) {
            data = JSON.parse(data)
            setInputTime(data['input_time'])
            setInputPktRate(data['input_pkt_rate'])
            setInputByteRate(data['input_byte_rate'])
            setOutputTime(data['output_time'])
            setOutputPktRate(data['output_pkt_rate'])
            setOutputByteRate(data['output_byte_rate'])
            setShowPlot(true)
        })
    }
   

    return (
        <>
            <Sidebar pageWrapId={'page-wrap'} outerContainerId={'outer-container'} />
            <h1 className="centered"> Node: {params.nodeId}</h1>
            { showPlot ? 
            <div>
                <Plot
                data={[
                    {
                        x: inputTime,
                        y: inputPktRate,
                        type: "scatter",
                        mode: "lines",
                        marker: {color: 'red'},
                        line: {shape: 'spline', width: 2}
                    },
                    {
                        x: outputTime,
                        y: outputPktRate,
                        type: "scatter",
                        mode: "lines",
                        marker: {color: 'blue'},
                        line: {shape: 'spline', width: 2}

                    }
                ]}
                config={{responsive: true}}
                style={{ width: "100%", height: "100%" }}
                />
            </div>
            :
            <p> processing plot .... </p>
            }
            
            
        </>
    )
}

export default NodeView;