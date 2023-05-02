const monoose=require('mongoose');
require('dotenv').config();
const connection= mongoose.connect(process.env.Mongo_Url)

module.exports={
    connection
}