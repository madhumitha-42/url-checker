from flask import Flask, request, jsonify
from flask_cors import CORS
from validator import URLValidator

app = Flask(__name__)
CORS(app)
validator = URLValidator()

@app.route('/check', methods=['POST'])
def check_url():
    data = request.json
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    result = validator.validate_url(url)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)