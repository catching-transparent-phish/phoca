# PHOCA
Tool to analyze and classify websites as originating from a MITM phishing toolkit or not. 
Supplementary material for CCS '21 paper ["Catching Transparent Phish: Analyzing and Detecting MITM Phishing Toolkits"](https://catching-transparent-phish.github.io/catching_transparent_phish.pdf).

Citation:

```
@article{kondracki2021catching,
    title={Catching Transparent Phish: Analyzing and Detecting MITM Phishing Toolkits},
    author={Kondracki, Brian and Azad, Babak Amin and Starov, Oleksii and Nikiforakis, Nick},
    booktitle={ACM Conference on Computer and Communications Security (CCS)},
    year={2021}
}
```

## Requirements
* python3.7

## Installation
Install Python dependencies using `python3.7 -m pip install -r requirements.txt`

## Usage
To access low-level network functions to create and send raw TCP packets, this tool requires sudo privilages.

Scan one website by specifying the domain or URL of the site:

`sudo ./phoca www.google.com`

Bulk scan multiple websites by supplying a csv containing one URL or domain per line:

`sudo ./phoca -r domains.csv`

Output results to a CSV file rather than terminal output:

`sudo ./phoca -r domains.csv -w results.csv`

JSON and CSV formats supported for output of raw feature data:

```
sudo ./phoca --raw-data --output-format json www.google.com | jq
{
  "www.google.com": {
    "classification": "Non-Phishing",
    "data": {
      "site": "www.google.com",
      "tcpSYNTiming": 5.626678466796875e-05,
      "tlsClientHelloTiming": 0.0029659271240234375,
      "tlsClientHelloErrorTiming": 0.003025054931640625,
      "tlsHandshakeTiming": 0.012071371078491211,
      ...
```

## Docker
Alternatively, you can use the supplied Docker image to run PHOCA from a Docker container, simplifying the setup process.
To do this, first build the image:

`sudo docker build -t phoca .`

Then, run the container, supplying the domain of interest:

`sudo docker run --rm phoca www.attacker.com`

If you would like to allow PHOCA to read domains from an input file, you must mount that file to the root of the container:

`sudo docker run -v /home/user/input.txt:/input.txt phoca -r input.txt`
