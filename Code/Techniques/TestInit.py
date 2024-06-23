import Net
import ImportData
from DeepCASE import preprocessData, contextBuilder, interpreterFit
import pandas as pd
import time
import sys
import torch
import tensorflow as tf
from tqdm import tqdm
import threading
from Traverse import *
import random

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

# write header for csv file
with open('DeepCASE.csv', 'w') as f:
    print("Writing header for csv file...")
    f.write("Machine; Number of alerts; Time active; [Full Graph List]; [Partial Graph List]; [Path List]; Continues; Number of events used; Completion Rate; Time Diff Path; Event Index\n")
    f.close()

machines = list(results.keys())
for key in machines:
    write_content = []
    print(f"Processing machine {key}...")
    BehaviorNet = Net.Net()

    for index, alert in results[key].iterrows():
        alert2 = Net.Alert(alert['Date_Time'], alert['Message'], alert['Protocol'], alert['Source'], alert['Source Port'], alert['Destination'], alert['Destination Port'], alert['Tactics'], alert['Index'])
        alert2.setCode(alert['Technique'])
        alert2.setCodeName(alert['Technique Name'])
        BehaviorNet.checkAlert(alert2)
    BehaviorNet.checkTimes()
    BehaviorNet.createEdges()
    

    selected_machine = key
    machine_data = results[selected_machine]
    start_time = machine_data['Date_Time'].min()
    end_time = machine_data['Date_Time'].max()
    time_active = end_time - start_time
    num_alerts = len(machine_data)
    graph_size = len(BehaviorNet.techniques)
    if graph_size == 0 or graph_size == 1:
        continue

    machine_context = context[machine_data.iloc[0]['Index']:machine_data.iloc[len(machine_data) - 1]['Index'] + 1]
    machine_events = events[machine_data.iloc[0]['Index']:machine_data.iloc[len(machine_data) - 1]['Index'] + 1]

    _, attention = interpreter.attention_query(machine_context, machine_events)

    # get all nodes. take the nodes from the latest phase
    last_nodes = []
    for node in BehaviorNet.techniques:
        current_phase = node.phase
        if len(last_nodes) == 0:
            last_nodes.append(node)
            continue
        last_nodes_phase = last_nodes[0].phase

        if current_phase > last_nodes_phase:
            last_nodes = [node]
        elif current_phase == last_nodes_phase:
            last_nodes.append(node)
    
    event_list = []
    for node in last_nodes:
        for alert in node.alerts:
            if alert.index % 2 == 0:
                event_list.append((alert.index, alert.date_time))
        
    random.shuffle(event_list)
    event_list = event_list[:min(10000000, len(event_list))]

    for event_index in tqdm(event_list):
        TempNet = BehaviorNet.copy()

        try:
            selected_event = machine_data[machine_data['Index'] == event_index[0]].iloc[0]
            selected_index = machine_data.index.get_loc(selected_event.name)
        except IndexError:
            print("Index out of bounds")
            print(f"Event index: {event_index}")
            exit()

        techniques_to_remove = []
        for node in TempNet.techniques:
            if node.start > selected_event['Date_Time']:
                techniques_to_remove.append(node)
            elif node.end > selected_event['Date_Time']:
                node.resetEnd(selected_event['Date_Time'])
        for node in techniques_to_remove:
            TempNet.techniques.remove(node)

        TempNet.edges = []
        TempNet.createEdges()
        used, start_time = traverseBehaviorRecursion(TempNet, machine_data, selected_index, attention, context)
        Time = selected_event['Date_Time'] - start_time
        continuous = isContinuous(TempNet.predicted_edges)
        completion_rate = completionRate(TempNet.edges, TempNet.predicted_edges, [node for node in TempNet.techniques if node.code == selected_event['Technique'].split('.')[0]][0])
        FullGraphList, PartialGraphList, PathList = getLists(BehaviorNet, TempNet)
        write_content.append(f"{selected_machine}; {num_alerts}; {time_active}; {FullGraphList}; {PartialGraphList}; {PathList}; {continuous}; {used}; {completion_rate}; {Time}; {selected_index}\n")
    
    with open('DeepCASE.csv', 'a') as f:
        for line in write_content:
            f.write(line)
        f.close()

    