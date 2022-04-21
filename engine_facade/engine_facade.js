const path = require('path');

const { PythonShell } = require("python-shell");


// export class engineFacade{

// }

// class engineFacade{
//     constructor(){}

//     parsePcap(filePath){
//         var python = require("python-shell");
//         var path = require("path");

//         var pcap_file = file;

//         console.log('reached get_parser!!');
//         console.log('filePath in connector', filePath);
//         var options = {
//             sciptPath: path.join(__dirname, '/../engine/'),
//             args: pcap_file
//         };
        
//     }

// }

function get_parser(filePath){

    var pcap_file = file;

    console.log('reached get_parser!!');
    console.log('filePath in connector', filePath);
    var options = {
        sciptPath: path.join(__dirname, '/../engine/'),
        args: pcap_file
    };
    let parser = new PythonShell('test_parser.py', options);
    parser.on('message', function(message){
        console.log('PYTHON SHELL MESSAGE', message);
    }) 

};


module.exports = { get_parser };


// export default get_parser;
