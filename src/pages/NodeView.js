import ThroughputCard from "../comps/ThroughputChart"


const NodeView = ({ data }) => {


    return (
        <ThroughputCard data = {data.throughput} />
        
    )

}

export default NodeView;