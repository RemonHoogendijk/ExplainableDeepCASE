# Evaluation Results
Each file has the pipeline results for one of the experiments run during the evaluation process.

| File                        | Experiment                                                                                          | File Size (KB) |
|-----------------------------|-----------------------------------------------------------------------------------------------------|----------------|
| DeepCASE_base.csv           | Baseline experiment                                                                                 | 75,756         |
| DeepCASE_phases_lateral.csv | Allows for lateral movement within a phase during graph generation.                                 | 117,029        |
| DeepCASE_phases_full.csv    | Allows for full movement between phases during graph generation. To both earlier and later phases.  | 20,702         |
| DeepCASE_Intermediate.csv   | Not removing direct connections when intermediate node is found in graph generation.                | 134,198        |
| DeepCASE_phases_expert.csv  | Alternative phase mapping based on feedback from cyber expert.                                      | 91,706         |
| DeepCASE_phases_random.csv  | Alternative phase mapping created randomly.                                                         | 502            |
| DeepCASE_techniques.csv     | Alternative mapping of events to MITRE ATT&CK Techniques.                                           | 83,695         |