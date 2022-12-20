import {APP_PORT} from "./config";
import {errorHandler,apiHandler} from "./middlewares";
import express from "express";
import routes from "./routes";
import { validator } from "./validators";
import { CustomJwtService } from "./services";
import jks, { sort } from "json-keys-sort";
import CryptoJS from "crypto-js";
const app = express();

app.use(express.urlencoded({extended:false}));

app.use(express.json());

app.use("/client",validator.apiAuth(),apiHandler,routes);

app.use(errorHandler);


  const system = {
    cpu: [
      {
        Caption: "Intel64 Family 6 Model 158 Stepping 9",
        Family: 205,
        Name: "Intel(R) Core(TM) i5-7300HQ CPU @ 2.50GHz",
        NumberOfCores: 8,
        ProcessorId: "BFEBFBFF000906E9",
        SerialNumber: "To Be Filled By O.E.M.",
        SocketDesignation: "U3E1",
        SystemName: "YASH"
      }
    ],
    disk: [
      {
        Index: 1,
        InterfaceType: "SCSI",
        Manufacturer: "(Standard disk drives)",
        Model: "WDC WDS500G2B0C-00PXH0",
        Partitions: 3,
        SerialNumber: "E823_8FA6_BF53_0001_001B_444A_4619_C416.",
        Size: 500105249280
      },
      {
        Index: 0,
        InterfaceType: "IDE",
        Manufacturer: "(Standard disk drives)",
        Model: "HGST HTS721010A9E630",
        Partitions: 0,
        SerialNumber: "JR1000BN11W25E",
        Size: 1000202273280
      }
    ],
    gpu: [
      {
        Description: "NVIDIA GeForce GTX 1050",
        Name: "NVIDIA GeForce GTX 1050"
      },
      {
        Description: "Intel(R) HD Graphics 630",
        Name: "Intel(R) HD Graphics 630"
      }
    ],
    motherboard: [
      {
        Description: "Base Board",
        Manufacturer: "HP",
        Name: "Base Board",
        Product: "836B",
        SerialNumber: "PGPUB018J940RQ"
      }
    ],
    ram: [
      {
        Capacity: 8589934592,
        DeviceLocator: "Bottom-Slot 1(left)",
        InterleavePosition: 1,
        Manufacturer: "Samsung",
        PartNumber: "M471A1K43CB1-CRC",
        SerialNumber: "2015610E"
      },
      {
        Capacity: 8589934592,
        DeviceLocator: "Bottom-Slot 2(right)",
        InterleavePosition: 2,
        Manufacturer: "A-DATA Technology",
        PartNumber: "",
        SerialNumber: 44480000
      }
    ],
  };
  
  // const sorted = jks.sort(system,true);
  // const signature = CryptoJS.SHA256(JSON.stringify(sorted)).toString();
  // sorted.createdAt= "20221219T171332";
  // sorted.deletedAt= "N/A";
  // const payload = {system:sorted,signature:signature};
  // const token = CustomJwtService.signSystemToken(payload);
  // console.log(token);

app.listen(APP_PORT,()=>console.log(`Listening on port ${APP_PORT}`));