import json
import pandas as pd
from flask import Flask, request
from flask_restplus import Resource, Api, reqparse, fields
from pymongo import MongoClient

import requests
import datetime

app = Flask(__name__)
api = Api(app,
          default="World Bank Economic Indicators",
          title="World Bank DataSet",
          description="Data Service for World Bank Economic Indicators."
          )

indicator_model = api.model('Indicator', {
    'indicator_id': fields.String
})


app.config['MONGO_DBNAME'] = 'xxxxx'
app.config['MONGO_URI'] = 'mongodb://xxxxxxxxxxx.mlab.com:xxxxxxx/xxxxxxxxxxxx'

myclient = MongoClient(app.config['MONGO_URI'])
mydb = myclient["xxxxxxxxxxx"]


@api.route('/collections')
class AddCountries(Resource):
    @api.response(404, 'Validation error')
    @api.response(200, 'OK')
    @api.response(201, 'Created')
    @api.doc(description="Import a collection from the data service.")
    @api.expect(indicator_model, validate=True)
    def post(self):
        indc = request.json
        # print(book['indicator_id'])
        indicator_id = indc['indicator_id']
        # Construct the URL
        json_url = 'http://api.worldbank.org/v2/countries/all/indicators/'+ indicator_id +'?date=2012:2017&format=json&per_page=2000'
        r = requests.get(json_url)
        json_data = r.json()
        if 'message' in json_data[0]:
            return {"message":'Invalid Indicator Id.'},404

        # Has this indicator already been imported?
        for x in mydb.list_collection_names():
            if indicator_id in str(x):
                # Yes it has been used before....Get the collection id
                col = mydb[indicator_id]
                q = col.find_one()
                return {"location": "/"+ indicator_id +"/" + q['collection_id']}, 200

        record = {}
        record['collection_id'] = indicator_id
        record['indicator'] = indicator_id
        record['indicator_value'] = list(json_data)[1][0]['indicator']['value']
        record['creation_time'] = str(datetime.datetime.now())
        record['entries'] = []
        for i in list(json_data)[1]:
            newdict = {}
            newdict['country'] = i['country']['value']
            newdict['date'] = i['date']
            newdict['value'] = i['value']
            record['entries'].append(newdict)

        mycol = mydb[indicator_id]
        x = mycol.insert_many([record])
        x = str(x.inserted_ids)
        x = x[11 :-3]
        myquery = {"collection_id": indicator_id}
        newvalues = {"$set": {"collection_id": x}}
        mycol.update_one(myquery, newvalues)

        output = {"location" : "/"+ indicator_id +"/" + x,
                  "collection_id" : x,
                  "creation_time": record['creation_time'],
                  "indicator" : record['indicator_value']
                }
        return output, 201


    
    @api.doc(description="Retrieve the list of available collections.")
    def get(self):
        result = []
        for x in mydb.list_collection_names():
            if 'system' not in str(x):
                mycol = mydb[x]
                q = mycol.find_one()
                new_dict = {}
                new_dict['location'] = '/'+ str(x) +'/' + q['collection_id']
                new_dict['collection_id'] = q['collection_id']
                new_dict['creation_time'] = q['creation_time']
                new_dict['indicator'] = q['indicator']
                result.append(new_dict)
        return result, 200


@api.route('/collections/<collection_id>')
@api.param('collection_id', 'Collection Id returned while creating Collection')
@api.response(404, 'Validation error')
@api.response(200, 'OK')
class Del_Collection(Resource):
    @api.doc(description="Deleting a collection with the data service.")
    def delete(self, collection_id):
        for x in mydb.list_collection_names():
            if 'system' not in x:
                mycol = mydb[x]
                q = mycol.find_one()
                if q['collection_id'] == collection_id:
                    mycol.drop()
                    return {"message": "Collection = {} is removed from the database!".format(collection_id)}, 200
        return {"message":'Invalid collection Id.'}, 404


    @api.doc(description="Retrieve a collection.")
    def get(self, collection_id):
        for x in mydb.list_collection_names():
            if 'system' not in x:
                mycol = mydb[x]
                q = mycol.find_one()
                # print(q)
                if q['collection_id'] == collection_id:
                    del q['_id']
                    # print(q)
                    return q, 200
        return {"message": 'Invalid collection Id.'}, 404

# Retrieve economic indicator value for given country and a year
@api.route('/collections/<collection_id>/<year>/<country>')
@api.param('collection_id', 'Collection Id returned while creating Collection')
@api.param('year', 'Year')
@api.param('country', 'Country')
@api.response(404, 'Validation error')
@api.response(200, 'OK')
class GetEcoIndicator(Resource):
    @api.doc(description="Retrieve economic indicator value for given country and a year.")
    def get(self, collection_id, year, country):
        for x in mydb.list_collection_names():
            if 'system' not in x:
                mycol = mydb[x]
                q = mycol.find_one()
                if q['collection_id'] == collection_id:
                    # Convert the entries to a pandas dataframe and check the match = ?
                    df = pd.DataFrame(q['entries'])
                    df.date = pd.to_numeric(df.date, errors='coerce').fillna(0).astype(str)
                    df = df[(df.country == country) & (df.date == year)]
                    result = {}
                    result['collection_id'] = q['collection_id']
                    result['indicator'] = q['indicator']
                    if df.empty:
                        result['message'] = 'Collection Id is valid. But No entry found for the year and country.'
                        return result, 404
                    else:
                        result['country'] = country
                        result['year'] = year
                        result['value'] = df.iloc[0]['value']
                        return result, 200
        return {"message": 'Invalid Collection Id.'}, 404


# HTTP operation: GET /<collections>/{collection_id}/{year}?q=<query>
qry = reqparse.RequestParser()
qry.add_argument('query', type=str, required=False, help='Example: top5 or bottom5')
@api.route('/collections/<collection_id>/<year>')
@api.param('collection_id', 'Collection Id returned while creating Collection')
@api.param('year', 'Year')
@api.response(404, 'Validation error')
@api.response(200, 'OK')
@api.expect(qry)
class GetTopBottomIndicator(Resource):
    @api.doc(description = 'Retrieve top/bottom economic indicator values for a given year.')
    def get(self, collection_id, year):
        args = qry.parse_args()
        sort_order = ''
        if args['query']:
            if 'TOP'.lower() == str(args['query'][:3]).lower():
                sort_order = 'TOP'
                try:
                    sort_value = int(args['query'][3:])
                    if sort_value < 1 or sort_value > 100:
                        return {"Message":"Invalid Query format. Query should be between 1 and 100."}, 404
                except ValueError:
                    return {"message" : "Invalid Query format. Query should be an integer."}, 404
            elif 'BOTTOM'.lower() == str(args['query'][:6]).lower():
                sort_order = 'BOTTOM'
                try:
                    sort_value = int(args['query'][6:])
                    if sort_value < 1 or sort_value > 100:
                        return {"Message":"Invalid Query format. Query should be between 1 and 100."}, 404
                except ValueError:
                    return {"message" : "Invalid Query format. Query should be an integer."}, 404
            else:
                return {"Message": "Invalid Query string. Please follow correct format as given in Example."}, 404

        for x in mydb.list_collection_names():
            if 'system' not in x:
                mycol = mydb[x]
                q = mycol.find_one()
                if q['collection_id'] == collection_id:
                    # Convert the entries to a pandas dataframe and check the match = ?
                    df = pd.DataFrame(q['entries'])
                    df.date = pd.to_numeric(df.date, errors='coerce').fillna(0).astype(str)
                    df = df[df.date == year]

                    result = {}
                    result['indicator'] = q['indicator']
                    result['indicator_value'] = q['indicator_value']
                    if df.empty:
                        result['entries'] = 'Collection Id is valid. But No entry found for the year and country.'
                        return result, 404
                    else:
                        # convert df to list of dictionaries
                        if not sort_order:
                            result['entries'] = q['entries']
                            return result, 200
                        else:
                            df.value = pd.to_numeric(df.value, errors='coerce').fillna(0)
                            df = df.sort_values(by='value', ascending=False)
                            if sort_order == 'TOP':
                                df = df.head(sort_value)
                                result['entries'] = df.to_dict(orient='records')
                                for rec in result['entries']:
                                    if rec['value'] == 0:
                                        rec['value'] = None
                                return result, 200
                            elif sort_order == 'BOTTOM':
                                df = df.tail(sort_value)
                                df = df.sort_values(by='value', ascending=True)
                                result['entries'] = df.to_dict(orient='records')
                                for rec in result['entries']:
                                    if rec['value'] == 0:
                                        rec['value'] = None
                                return result, 200
        return {"message": "Invalid Collection Id"}, 404


if __name__ == '__main__':
    # run the application
    app.run(debug=True)
