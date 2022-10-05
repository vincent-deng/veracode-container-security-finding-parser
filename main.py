import json
import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--inspect_file', type=str, required=False,
                        default='inspect.json', help='please input the inspect json file')
    parser.add_argument('-s', '--scan_file', type=str, required=False,
                        default='scan.json', help='please input the scan json file')
    parser. add_argument('-d', '--detailed_report', required=False,
                         action='store_true', help='see detailed CWEs for each layer')
    args = parser.parse_args()

    inspect_file = args.inspect_file
    scan_file = args.scan_file
    detailed_report = args.detailed_report

    with open(inspect_file, 'r') as f:
        inspect_data = json.load(f)

    if 'docker' not in inspect_data.keys() or \
            'RootFS' not in inspect_data['docker'].keys() or \
            'Layers' not in inspect_data['docker']['RootFS'].keys():
        raise Exception('cannot find layers in inspect json')

    layers = inspect_data['docker']['RootFS']['Layers']

    layer_vulnerabilities_dict = dict()

    layer_index = 1

    for layer in layers:
        layer_vulnerabilities_dict[layer] = {'vulnerabilities': set(), 'layer_num': layer_index}
        layer_index += 1

    with open(scan_file, 'r') as f:
        scan_data = json.load(f)

    if 'findings' not in scan_data.keys() or \
            'vulnerabilities' not in scan_data['findings'].keys() or \
            'matches' not in scan_data['findings']['vulnerabilities']:
        raise Exception('cannot find vulnerabilities in the scan data')

    try:
        image = scan_data['findings']['docker']['image']
        base_image = {'OS Family': scan_data['findings']['iac']['Metadata']['OS']['Family'],
                      'OS Name': scan_data['findings']['iac']['Metadata']['OS']['Name']}
    except KeyError:
        image = 'unknown'
        base_image = {'OS Family': 'unknown', 'OS Name': 'unknown'}

    for finding in scan_data['findings']['vulnerabilities']['matches']:
        if 'artifact' not in finding.keys() or 'locations' not in finding['artifact']:
            raise Exception('cannot find vulnerability artifact in scan results')
        if 'vulnerability' not in finding.keys():
            raise Exception('finding structure missing vulnerabilities')
        vulnerability = finding['vulnerability']
        for layer in finding['artifact']['locations']:
            layer_id = layer['layerID']
            if layer_id not in layer_vulnerabilities_dict.keys():
                raise Exception('scan data and inspect data not matching')

            layer_vulnerabilities_dict[layer_id]['vulnerabilities'].add(
                (
                    vulnerability['id'], vulnerability['severity']
                    # vulnerability['description'],
                    # vulnerability['namespace']
                )
            )

    print('Scanned Image: ' + image + ', Base Image OS Family: ' +
          base_image['OS Family'] + ' , Base Image OS Name: ' + base_image['OS Name'] + '\n')

    for layer_id in layer_vulnerabilities_dict:
        if layer_vulnerabilities_dict[layer_id]['layer_num'] == 1:
            print('Base Image (based on the first Layer in veracode inspect command) has ' +
                  str(len(layer_vulnerabilities_dict[layer_id]['vulnerabilities'])) + ' vulnerabilities.\n')

    for layer_id in layer_vulnerabilities_dict:
        layer = layer_vulnerabilities_dict[layer_id]
        layer_num = layer['layer_num']
        vul_count = len(layer['vulnerabilities'])
        print('Layer ' + str(layer_num) + ' (' + layer_id + ') has a count of ' + str(vul_count) + ' vulnerabilities.')

    if detailed_report:
        print('\n')

        for layer_id in layer_vulnerabilities_dict:
            layer = layer_vulnerabilities_dict[layer_id]
            layer_num = layer['layer_num']
            print('Layer ' + str(layer_num) + ' Vulnerabilities:')
            print(layer['vulnerabilities'])
            # print(layer['vulnerabilities'])


if __name__ == "__main__":
    main()
