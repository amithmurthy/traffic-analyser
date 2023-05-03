import ThroughputCard from "../comps/ThroughputChart"
import { useParams } from "react-router-dom"
import Sidebar from "../comps/Sidebar";
import Plot from "react-plotly.js"
import { useEffect, useState } from "react";
import { Grid, Paper, Button, Select, InputLabel, MenuItem, FormControl } from "@mui/material";
import { makeStyles } from "@material-ui/core";

const useStyles = makeStyles((theme) => ({
    root: {
      flexGrow: 1,
    },
    paper: {
      padding: theme.spacing(2),
      textAlign: "center",
      color: theme.palette.text.secondary,
    },
}));


const NodeView = () => {
    let params = useParams();
    const [inputTime, setInputTime] = useState([])
    const [inputPktRate, setInputPktRate] = useState([])
    const [inputByteRate, setInputByteRate] = useState([])
    const [outputTime, setOutputTime] = useState([])
    const [outputPktRate, setOutputPktRate] = useState([])
    const [outputByteRate, setOutputByteRate] = useState([])
    const [showPlot, setShowPlot] = useState(false)

    const [flowScatterPlotData, setFlowScatterPlotData] = useState(new Map())
    const [toggleByteRate, setToggleByteRate] = useState(false)
    const [samplingRate, setSamplingRate] = useState(60)
    
    const request = {'getNodeView': params?.nodeId}
    


    if(!showPlot){
        window.electron.facadeAPI.sendRequest(request)
        window.electron.handle('getNodeView', (event,data) => function(event,data) {
            data = JSON.parse(data)
            setInputTime(data['throughput']['input_time'])
            setInputPktRate(data['throughput']['input_pkt_rate'])
            setInputByteRate(data['throughput']['input_byte_rate'])
            setOutputTime(data['throughput']['output_time'])
            setOutputPktRate(data['throughput']['output_pkt_rate'])
            setOutputByteRate(data['throughput']['output_byte_rate'])
            setFlowScatterPlotData(data['scatter_plot'])
            setShowPlot(true)
        })
    }
   

    const toggleThroughput = () =>{
        setToggleByteRate(!toggleByteRate)
    }

    const classes = useStyles();

    const samplingRates = [{value: 30, name: '30 seconds'}, {value: 60, name:'1 min'}, {value: 120, name:'2 mins'}, {value: 240, name:'4 mins'} ]

    const handleSamplingRateChange = (event) => {
        setSamplingRate(event.target.value)
        const request = {'configureNodeThroughputSamplingRate': {'node': params?.nodeId, 'sampling_rate': event.target.value}}
        window.electron.facadeAPI.sendRequest(request)
        window.electron.handle('configureNodeThroughputSamplingRate', (event, data) => function(event, data){
            data = JSON.parse(data)
            setInputTime(data['throughput']['input_time'])
            setInputPktRate(data['throughput']['input_pkt_rate'])
            setInputByteRate(data['throughput']['input_byte_rate'])
            setOutputTime(data['throughput']['output_time'])
            setOutputPktRate(data['throughput']['output_pkt_rate'])
            setOutputByteRate(data['throughput']['output_byte_rate'])
        })
    }


    return (
        <>
            <Sidebar pageWrapId={'page-wrap'} outerContainerId={'outer-container'} />
            <h1 className="centered"> Node: {params.nodeId}</h1>
            
            { showPlot ? 
            <div className={classes.root}>
            <Grid container spacing={3} direction={"column"}>
                    <Grid item xs={12} sm={6} md={3}>
                        <Paper className={classes.paper}>
                        <h3> Node Flows  </h3>
                        <Plot
                        data={[
                            {
                                x: flowScatterPlotData['input_duration'],
                                y: flowScatterPlotData['input_size'],
                                type: "scatter",
                                mode: "markers",
                                marker: {color: 'red'},
                            },
                            {
                                x: flowScatterPlotData['output_duration'],
                                y: flowScatterPlotData['output_size'],
                                type: "scatter",
                                mode: "markers",
                                marker: {color: 'blue'},
                            }
                        ]}
                        config={{responsive: true}}
                        style={{ width: "100%", height: "100%" }}
                        />
                        </Paper>
                    </Grid>

                    <Grid item xs={12} sm={6} md={3}>
                        <Paper className={classes.paper}>
                        <div>
                            <Grid container direction={'row'} spacing={2}>
                            <Grid item>
                                <Button onClick={toggleThroughput} variant="contained">Toggle throughput</Button>
                            </Grid>
                                <Grid item>
                                    <div>
                                    <FormControl sx={{ m: 1, minWidth: 80 }}>
                                    <InputLabel> Sampling Rate</InputLabel>
                                        <Select
                                        value={samplingRate}
                                        onChange={handleSamplingRateChange}
                                        autoWidth
                                        label="Sampling Rate"
                                        >
                                            {samplingRates.map((rate, index) => (<MenuItem value={rate.value} key={index}> {rate.name} </MenuItem>))}
                                        </Select>
                                    </FormControl>
                                    </div>
                                </Grid>
                            </Grid>
                        </div>
                            <Plot
                            data={[
                                {
                                    x: inputTime,
                                    y: toggleByteRate ? inputByteRate : inputPktRate,
                                    type: "scatter",
                                    mode: "lines",
                                    fill: 'tozeroy',
                                    marker: {color: 'red'},
                                    line: {shape: 'spline', width: 2}
                                },
                                {
                                    x: outputTime,
                                    y: toggleByteRate ? outputByteRate : outputPktRate,
                                    type: "scatter",
                                    mode: "lines",
                                    fill: 'tozeroy',
                                    marker: {color: 'blue'},
                                    line: {shape: 'spline', width: 2}

                                }
                            ]}
                            config={{responsive: true}}
                            style={{ width: "100%", height: "100%" }}
                            />
                            
                        </Paper>
                    </Grid>   


                    

            </Grid>
            </div>
            :
            <p> processing plot .... </p>
            }
            
        </>
    )
}

export default NodeView;