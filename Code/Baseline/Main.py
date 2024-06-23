import Net
import ImportData
from DeepCASE import preprocessData, contextBuilder, interpreterFit
import pandas as pd
import time
import sys
import torch
import tensorflow as tf
from Traverse import *

print("Importing data...")
df = ImportData.importJson('Dev/Data/suricata_alert.json')

print("Preprocessing data...")
print("\tGetting host IP addresses...")
ip_addresses = []
# Get all unique IP addresses from source and destination and add them to the list
for index, alert in df.iterrows():
    if alert['Source'] not in ip_addresses:
        ip_addresses.append(alert['Source'])
    if alert['Destination'] not in ip_addresses:
        ip_addresses.append(alert['Destination'])

results = {}

print("\tFiltering data...")
for ip in ip_addresses:
    df_filtered = df[(df['Source'] == ip) | (df['Destination'] == ip)]
    results[ip] = df_filtered.copy()
    
# Create new df with the headers timestamp, event, machine
# - timestamp: the timestamp of the event
# - event: the event that happened (alert message)
# - machine: results keys (IP addresses)
print("\tCreating merged data for DeepCASE...")
row_list = []
i = 0
for key in results:
    results[key]['Index'] = range(i, i + len(results[key]))
    i += len(results[key])
    for index, alert in results[key].iterrows():
        dict1 = {} 
        dict1.update({'timestamp': alert['Date_Time'], 'event': alert['Message'], 'machine': key})
        row_list.append(dict1)
MergedData = pd.DataFrame(row_list)
# write the data to a csv file
MergedData.to_csv('Dev/Data/MergedData.csv', index=False)

print("Running DeepCASE...")
context, events, labels, mapping = preprocessData('Dev/Data/MergedData.csv', event_timeout=86400000000000)
context_builder = contextBuilder(context, events, epochs=10, input_size = 200, output_size = 200)
clusters, interpreter = interpreterFit(context_builder, context, events, features=200)
# interpreter = interpreterFit(context_builder, context, events, features=200)

while True:
    print("Select a machine:")
    machines = list(results.keys())
    for i in range(0, len(machines), 3):
        for j in range(i, min(i+3, len(machines))):
            print(f"{j+1}. {machines[j]}", end="\t\t")
        print()
    machine_index = input("Enter the index of the machine: ")
    try:
        machine_index = int(machine_index)
        if machine_index == -1:
            print("Exiting...")
            break
        if machine_index < 1 or machine_index > len(results):
            print("Incorrect index. Please enter a valid index.")
            raise ValueError
    except ValueError:
        print("Invalid input. Please enter a valid index.")
        continue

    print("Creating graphs...")
    key = machines[machine_index - 1]
    print("\tNumber of alerts: ", len(results[key]))
    BehaviorNet = Net.Net()
    print("\tLooping through alerts...")
    for index, alert in results[key].iterrows():
        alert2 = Net.Alert(alert['Date_Time'], alert['Message'], alert['Protocol'], alert['Source'], alert['Source Port'], alert['Destination'], alert['Destination Port'], alert['Tactics'], alert['Index'])
        alert2.setCode(alert['Technique'])
        alert2.setCodeName(alert['Technique Name'])
        BehaviorNet.checkAlert(alert2)
    BehaviorNet.checkTimes()
    BehaviorNet.createEdges()

    print("\tPrinting stats...")
    selected_machine = key
    machine_data = results[selected_machine]
    start_time = machine_data['Date_Time'].min()
    end_time = machine_data['Date_Time'].max()
    time_active = end_time - start_time
    num_alerts = len(machine_data)
    graph_size = len(BehaviorNet.techniques)

    print(f"\nMachine Overview:")
    print(f"Machine: {selected_machine}")
    print(f"Time Active: {time_active}")
    print(f"Number of Alerts: {num_alerts}")
    print(f"Graph Size: {graph_size}")

    # Get the range of indexes for selection
    sequence_range = range(1, len(machine_data) + 1)

    machine_context = context[machine_data.iloc[0]['Index']:machine_data.iloc[len(machine_data) - 1]['Index'] + 1]
    machine_events = events[machine_data.iloc[0]['Index']:machine_data.iloc[len(machine_data) - 1]['Index'] + 1]

    _, attention = interpreter.attention_query(machine_context, machine_events)

    BehaviorNet.checkTimes()
    BehaviorNet.edges = []
    BehaviorNet.createEdges()
    BehaviorNet.createGraph()
    time.sleep(1)

    # Allow user to select a sequence for analysis
    while True:
        print("\nSelect a sequence to analyze:")
        print(f"Enter the index of the sequence ({sequence_range.start}-{sequence_range.stop - 1}): ")
        try:
            event_index = int(input())
        except ValueError:
            print("Invalid input. Please enter a valid index.")
            continue
        if event_index == -1:
            print("Exiting...")
            break
        elif event_index not in sequence_range:
            print("Invalid input. Please enter a valid index.")
            continue

        event_index -= 1

        TempNet = BehaviorNet.copy()

        selected_event = machine_data.iloc[event_index]
        selected_sequence_index = selected_event['Index']
        selected_context_labeled = context[selected_sequence_index]
        selected_event_labeled = events[selected_sequence_index]
        selected_Attention = attention[event_index]

        # Print the selected sequence
        print("Selected Sequence:")
        print(selected_event)
        print(selected_sequence_index)
        print(selected_context_labeled)
        print(selected_event_labeled)
        print(selected_Attention)

        print(selected_sequence_index)
        techniques_to_remove = []
        for node in TempNet.techniques:
            if node.start > selected_event['Date_Time']:
                techniques_to_remove.append(node)
            elif node.end > selected_event['Date_Time']:
                node.resetEnd(selected_event['Date_Time'])
        for node in techniques_to_remove:
            TempNet.techniques.remove(node)
                
        # traverseMachine(selected_sequence_index, selected_context_labeled, selected_Attention, TempNet, machine_data, event_index)
#         weighted_edges_ascending(TempNet, machine_data, event_index, attention, context, events)

#         TempNet.edges = []
#         TempNet.createEdges()
#         TempNet.createGraph()

#         TempNet.predicted_edges = []
#         weighted_edges(TempNet, machine_data, event_index, attention, context, events)
    
#         TempNet.edges = []
#         TempNet.createEdges()
#         TempNet.createGraph()

        TempNet.edges = []
        TempNet.createEdges()
        used, _ = traverseBehaviorRecursion(TempNet, machine_data, event_index, attention, context)
        print(used)

        print(completionRate(TempNet.edges, TempNet.predicted_edges, [node for node in TempNet.techniques if node.code == selected_event['Technique'].split('.')[0]][0]))
        
        TempNet.edges = []
        TempNet.createEdges()
        TempNet.createGraph()