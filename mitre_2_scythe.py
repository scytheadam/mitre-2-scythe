import argparse
import json
import yaml


if __name__ == '__main__':
    print("Running...\n")

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--yamlfile', required=True,
        help='''
            The target (local) MITRE Adversary Emulation YAML file.
        ''',
    )
    parser.add_argument(
        '--outfile',
        help='''
            Name of the output file. (Default: '<threat_name>.json')
        ''',
    )
    args = parser.parse_args()

    # First, try for a local file
    try:
        with open(args.yamlfile) as f:
            mitre_plan = yaml.load(f, Loader=yaml.FullLoader)
    except (FileNotFoundError, IsADirectoryError, OSError) as e:
        print("Error loading file: '%s'." % args.yamlfile)
        print(e)
        exit()
    except yaml.scanner.ScannerError:
        print("Invalid YAML: '%s'." % args.yamlfile)
        exit()

    # Placeholder Object for the Steps:
    command_steps = []
    # Now, Parse the YAML Object
    for item in mitre_plan:
        for attr in item:
            if attr == "platforms":
                for platform in item[attr]:
                    for runtime in item[attr][platform]:
                        if runtime == "cmd" or runtime == "psh":
                            command_steps.append(
                                (
                                    runtime,
                                    item[attr][platform][runtime]['command'],
                                    item['technique']['attack_id']
                                )
                            )
                        # end IF
                    # end for runtime
                # end for platform
            # end if attr
        # end for attr
    # end for item

    threat_name = mitre_plan[0][
        'emulation_plan_details']['adversary_name'].replace(" ", "_")
    threat_desc = mitre_plan[0][
        'emulation_plan_details'
        ]['adversary_description']

    # Build base SCYTHE Threat Object:
    scythe_threat = {
        "threat": {
            "category": "User-Defined",
            "description": threat_desc,
            "display_name": threat_name,
            "name": threat_name,
            "operating_system_name": "windows",
            "script": {
                "0": {
                    "conf": {
                        '--cp': "127.0.0.1:443",
                        '--multipart': "10240",
                        '--secure': True,
                    },
                    "module": "https",
                    "type": "initialization"
                },
                "1": {
                    "module": "loader",
                    "module_to_load": "run",
                    "request": "--load run",
                    "type": "message"
                },
                "2": {
                    "module": "loader",
                    "module_to_load": "upsh",
                    "request": "--load upsh",
                    "type": "message"
                }
            },
            "signature": "3ce1cbeedb097e1a0c3b83ebdd6c955a7433cf29"
        }
    }

    # Parse out the MITRE Steps, into SCYTHE actions
    for command in command_steps:
        # Set Step Number
        step_num = len(scythe_threat['threat']['script'])
        # Change syntax based on command type
        if command[0] == "cmd":
            module = "run"
            depends_on = "93b6b9cf-78d2-45ee-a174-08290fdf73db"
            request = "cmd /c " + command[1]
        elif command[0] == "psh":
            # module = "upsh"
            module = "run"
            depends_on = "ed8a7322-630d-4cc1-b065-8c2361d9f45d"
            # request = "--cmd " + command[1]
            request = "cmd /c " + command[1]
        # Create the Object
        scythe_threat['threat']['script'][step_num] = {
            "type": "message",
            "module": module,
            "depends_on": depends_on,
            "request": request.rstrip('\r\n'),
            "rtags": [
                command[2]
            ]
        }

    # Get the desired JSON file name, or use Threat Name
    if args.outfile:
        file_name = args.outfile
    else:
        file_name = "%s_scythe_threat.json" % threat_name

    # Output the Threat File
    with open(file_name, "w") as dest_file:
        json.dump(scythe_threat, dest_file, indent=4)

    print("Created SCYTHE Threat File: '%s'!" % file_name)

    print("\n ...Exiting.\n")
    exit()
