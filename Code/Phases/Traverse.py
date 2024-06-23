from collections import deque

def weighted_edges(TempNet, machine_data, event_index, attention, context, events):
    starting_event = machine_data.iloc[event_index]
    starting_node = [node for node in TempNet.techniques if node.code == starting_event['Technique'].split('.')[0]]
    # for each sequence in the machine data get the attention values
    while event_index >= 0:
        selected_event = machine_data.iloc[event_index]
        selected_sequence_index = selected_event['Index']
        selected_context_labeled = context[selected_sequence_index]
        selected_context_array = [item.item() for item in selected_context_labeled]
        selected_event_labeled = events[selected_sequence_index]
        selected_Attention = attention[event_index]
        # get each unique technique in the sequence from context
        unique_techniques = list(set(selected_context_array))
        # remove the techniques that are the same as the event
        unique_techniques = [technique for technique in unique_techniques if technique != selected_event_labeled.item()]

        if len(unique_techniques) > 0:
            # for each technique get the max attention values
            # get the node of selected event
            selected_node = [node for node in TempNet.techniques if node.code == selected_event['Technique'].split('.')[0]]

            for technique in unique_techniques:
                indexes = [(selected_Attention[i], i) for i in range(len(selected_Attention)) if selected_context_labeled[i] == technique]
                max_attention_index = max(indexes, key=lambda x: x[0])[1]
                if (event_index - 10 + max_attention_index) < 0:
                    event_index = -1
                    break
                # get the node of the max attention technique
                node_technique = machine_data.iloc[event_index - 10 + max_attention_index]['Technique'].split('.')[0]
                max_attention_node = [node for node in TempNet.techniques if node.code == node_technique]

                # check if there is an edge between the techniques and the event of the sequence
                # if there is no edge add the edge
                # if there is an edge, keep track of the attention value (add it, average it, something)
                for node in selected_node:
                    for new_node in max_attention_node:
                        if node == new_node:
                            continue
                        if any(new_node == edge[0] and node == edge[1] for edge in TempNet.predicted_edges):
                            for edge in TempNet.predicted_edges:
                                if new_node == edge[0] and node == edge[1]:
                                    edge[2].append(selected_Attention[max_attention_index].item())
                        else:
                            TempNet.predicted_edges.append([new_node, node, [selected_Attention[max_attention_index].item()]])
        event_index -= 1
    print("Predicted edges: ", len(TempNet.predicted_edges))
    results = []
    for edge in TempNet.predicted_edges:
        edge[2] = sum(edge[2]) / len(edge[2])
        # edge[2] = sum(edge[2])
        if edge[0] != edge[1]:
            results.append(edge)
        else:
            print(f"Removing because edge goes to itself: {edge[0].code} -> {edge[1].code}")
    
    # for node in TempNet.techniques:
    #     # Collect all predicted edges for this node
    #     incomming = [edge for edge in results if edge[1] == node]
    #     outgoing = [edge for edge in results if edge[0] == node]
    #     if len(incomming) > 0 and len(outgoing) == 0 and node not in starting_node:
    #         # Remove incomming edges from results
    #         results = [edge for edge in results if edge not in incomming]
    
    # If edge goes both ways. Only take the edge with the highest attention value
    # results_temp = results.copy()
    # for edge in results_temp:
    #     for second_edge in results_temp:
    #         if edge[0] == second_edge[1] and edge[1] == second_edge[0]:
    #             try:
    #                 if edge[2] > second_edge[2]:
    #                     results.remove(second_edge)
    #                 else:
    #                     results.remove(edge)
    #             except ValueError:
    #                 continue

    # adjacency_list = create_adjacency_list(TempNet.techniques, TempNet.predicted_edges)

    # # Remove edges that do not have a path to the starting node
    # for node in TempNet.techniques:
    #     if node not in starting_node:
    #         if not has_path_bfs(adjacency_list, node, starting_node[0]):
    #             print(f"Node {node.code} does not have a path to the starting node")
    #             results_temp = results.copy()
    #             for edge in results_temp:
    #                 if edge[0] == node or edge[1] == node:
    #                     print(f"Removing edge: {edge[0].code} -> {edge[1].code}")
    #                     results.remove(edge)
    #         else:
    #             print(f"Node {node.code} has a path to the starting node")
    
    TempNet.predicted_edges = results

def weighted_edges_ascending(TempNet, machine_data, event_index, attention, context, events):
    starting_event = machine_data.iloc[event_index]
    starting_node = [node for node in TempNet.techniques if node.code == starting_event['Technique'].split('.')[0]]
    # for each sequence in the machine data get the attention values
    counter = 0
    while counter <= event_index:
        selected_event = machine_data.iloc[counter]
        selected_sequence_index = selected_event['Index']
        selected_context_labeled = context[selected_sequence_index]
        selected_context_array = [item.item() for item in selected_context_labeled]
        selected_event_labeled = events[selected_sequence_index]
        selected_Attention = attention[counter]
        # get each unique technique in the sequence from context
        unique_techniques = list(set(selected_context_array))
        # remove the techniques that are the same as the event
        unique_techniques = [technique for technique in unique_techniques if technique != selected_event_labeled.item()]

        if len(unique_techniques) > 0:
            # for each technique get the max attention values
            # get the node of selected event
            selected_node = [node for node in TempNet.techniques if node.code == selected_event['Technique'].split('.')[0]]

            technique_sequence_list = {}
            for i in range(len(selected_context_labeled)):
                for node in TempNet.techniques:
                    if counter - 10 + i < 0:
                        continue
                    if node.code == machine_data.iloc[counter - 10 + i]['Technique'].split('.')[0] and node.code != selected_event['Technique'].split('.')[0]:
                        technique_sequence_list[i] = [node, selected_Attention[i].item()]
            # print("Technique Sequence List: ", technique_sequence_list)
            
            for i, (node, node_attention) in technique_sequence_list.items():
                edge_added = False
                for j, (second_node, second_attention) in technique_sequence_list.items():
                    if i < j and node != second_node:
                        if any((node, second_node) == (edge[0], edge[1]) for edge in TempNet.predicted_edges):
                            # Add edge from second node to selected_node. First check if that edge already exists
                            # if it does, update the attention value
                            # if it does not, add the edge
                            for sel_node in selected_node:
                                if any((second_node, sel_node) == (edge[0], edge[1]) for edge in TempNet.predicted_edges):
                                    for edge in TempNet.predicted_edges:
                                        if second_node == edge[0] and sel_node == edge[1]:
                                            edge[2].append(second_attention)
                                            edge_added = True
                                else:
                                    TempNet.predicted_edges.append([second_node, sel_node, [second_attention]])
                                    edge_added = True
                if not edge_added:
                    # Add edge from node to selected_node. First check if that edge already exists
                    for sel_node in selected_node:
                        if node == sel_node:
                            continue
                        if any((node, sel_node) == (edge[0], edge[1]) for edge in TempNet.predicted_edges):
                            for edge in TempNet.predicted_edges:
                                if node == edge[0] and sel_node == edge[1]:
                                    edge[2].append(node_attention)
                        else:
                            TempNet.predicted_edges.append([node, sel_node, [node_attention]])

            # for each technique in the sequence. check if it has attention higher than 1/len(selected_context_labeled)
            # if it does, check if it has a connection to one of the next techniques in the sequence that also has an attention higher than 1/len(selected_context_labeled)
            # continue this until the end of the sequence. if there is no longer an existing edge. Add the edge from that item to the current event
            
                

            # for technique in unique_techniques:
            #     indexes = [(selected_Attention[i], i) for i in range(len(selected_Attention)) if selected_context_labeled[i] == technique]
            #     if len(indexes) == 0:
            #         continue
            #     max_attention_index = max(indexes, key=lambda x: x[0])[1]
            #     if (counter - 10 + max_attention_index) < 0:
            #         continue
            #     # get the node of the max attention technique
            #     node_technique = machine_data.iloc[counter - 10 + max_attention_index]['Technique'].split('.')[0]
            #     max_attention_node = [node for node in TempNet.techniques if node.code == node_technique]

            #     # check if there is an edge between the techniques and the event of the sequence
            #     # if there is no edge add the edge
            #     # if there is an edge, keep track of the attention value (add it, average it, something)
            #     for node in selected_node:
            #         for new_node in max_attention_node:
            #             if node == new_node:
            #                 continue
            #             if any(new_node == edge[0] and node == edge[1] for edge in TempNet.predicted_edges):
            #                 for edge in TempNet.predicted_edges:
            #                     if new_node == edge[0] and node == edge[1]:
            #                         edge[2].append(selected_Attention[max_attention_index].item())
            #             else:
            #                 TempNet.predicted_edges.append([new_node, node, [selected_Attention[max_attention_index].item()]])
        counter += 1
    print("Predicted edges (Ascending): ", len(TempNet.predicted_edges))

    print("Predicted edges: ", len(TempNet.predicted_edges))
    results = []
    for edge in TempNet.predicted_edges:
        edge[2] = sum(edge[2]) / len(edge[2])
        # edge[2] = sum(edge[2])
        if edge[0] != edge[1]:
            results.append(edge)
        if edge[0].code == "T1659" and edge[0].phase == 2:
            print(f"Edge: {edge[0].code} -> {edge[1].code} with attention {edge[2]}")

    print("Length of Result", len(results))
        
    for node in TempNet.techniques:
        # Collect all predicted edges for this node
        incomming = [edge for edge in results if edge[1] == node]
        outgoing = [edge for edge in results if edge[0] == node]
        if len(incomming) > 0 and len(outgoing) == 0 and node not in starting_node:
            # Remove incomming edges from results
            print("Removing because no outgoing edge")
            results = [edge for edge in results if edge not in incomming]

    # print("This shit should print but fore some reason it is not...")
    # print("Length of Result", len(results))
    # for i in range(len(results)):
    #     print(f"Edge: {results[i][0].code} -> {results[i][1].code} with attention {results[i][2]}")
    
    # If edge goes both ways. Only take the edge with the highest attention value
    results_temp = results.copy()
    for edge in results_temp:
        for second_edge in results_temp:
            if edge[0] == second_edge[1] and edge[1] == second_edge[0]:
                try:
                    if edge[2] > second_edge[2]:
                        results.remove(second_edge)
                    else:
                        results.remove(edge)
                except ValueError:
                    continue

    adjacency_list = create_adjacency_list(TempNet.techniques, TempNet.predicted_edges)

    # Remove edges that do not have a path to the starting node
    for node in TempNet.techniques:
        if node not in starting_node:
            if not has_path_bfs(adjacency_list, node, starting_node[0]):
                print(f"Node {node.code} does not have a path to the starting node")
                results_temp = results.copy()
                for edge in results_temp:
                    if edge[0] == node or edge[1] == node:
                        print(f"Removing edge: {edge[0].code} -> {edge[1].code}")
                        results.remove(edge)
            else:
                print(f"Node {node.code} has a path to the starting node")
    
    TempNet.predicted_edges = results

def getChildren(node, edges):
    childrenList = []
    for edge in edges:
        if edge[1] == node:
            childrenList.append(edge[0])
    return childrenList

# For each node in the graph, check if it has a path in the predicted edges towards the target node. If no path exists, remove all edges connected to the node
def has_path_bfs(adjacency_list, start, end):
    visited = set()
    queue = [start]
    while queue:
        node = queue.pop(0)
        if node == end:
            return True
        if node not in visited:
            visited.add(node)
            queue.extend(adjacency_list[node])
    return False

def create_adjacency_list(nodes, edges):
    adjacency_list = {}
    for node in nodes:
        adjacency_list[node] = []
    for edge in edges:
        adjacency_list[edge[0]].append(edge[1])
        adjacency_list[edge[1]].append(edge[0])
    return adjacency_list

def traverseMachine(selected_sequence_index, selected_context_labeled, selected_Attention, TempNet, machine_data, event_index, context, attention):
    iterations = 0
    max_iterations = event_index+1
    current_nodes = []
    while iterations < max_iterations:
        # get the index of the max attention
        indexes = [(selected_Attention[i], i) for i in range(len(selected_Attention)) if selected_Attention[i] > (1/len(selected_context_labeled))]
        max_attention_index = max(indexes, key=lambda x: x[0])[1]
        if not indexes or (event_index - 10 + max_attention_index) < 0:
            print("No more events to analyze")
            # Remove duplicates from predicted edges
            print("Predicted edges: ", len(TempNet.predicted_edges))
            TempNet.predicted_edges = list(set(TempNet.predicted_edges))
            print("Predicted edges: ", len(TempNet.predicted_edges))
            return

        # get the new node
        new_event = machine_data.iloc[event_index]
        new_event_technique = new_event['Technique'].split('.')[0]
        new_nodes = [node for node in TempNet.techniques if node.code == new_event_technique]
        
        # check if we have a current node
        if len(current_nodes) > 0:
            # check if the current node is the same as the new node
            if current_nodes != new_nodes:
                # add edge and update current node
                for node in current_nodes:
                    for new_node in new_nodes:
                        if (new_node, node) in TempNet.predicted_edges:
                            continue
                        else:
                            TempNet.predicted_edges.append((new_node, node, 0.1))
                current_nodes = new_nodes
        else:
            # add the new node as the current node
            current_nodes = new_nodes

        # update the event values for next iteration
        event_index = event_index - 10 + max_attention_index
        selected_sequence_index = machine_data.iloc[event_index]['Index']
        selected_context_labeled = context[selected_sequence_index]
        selected_Attention = attention[event_index]

        iterations += 1
    # Remove duplicates from predicted edges
    print("Predicted edges: ", len(TempNet.predicted_edges))
    TempNet.predicted_edges = list(set(TempNet.predicted_edges))
    print("Predicted edges: ", len(TempNet.predicted_edges))

def traverseBehaviorRecursion(TempNet, machine_data, event_index, attention, context, node = None, used = 0):
    # get the node of the starting event
    if node is not None:
        if node.phase == 1:
            return used, 0
    selected_event = machine_data.iloc[event_index]
    selected_sequence_index = selected_event['Index']
    selected_context_labeled = context[selected_sequence_index]
    selected_Attention = attention[event_index]
    selected_nodes = [node for node in TempNet.techniques if node.code == selected_event['Technique'].split('.')[0]]
    used_copy = used

    start_time = machine_data.iloc[event_index]['Date_Time']

    if node is not None:
        selected_nodes = [node]
    
    # for this node traverse the sequences untill we find the next node. Then add the edge and call the function again for that node
    while event_index >= 0:
        # Get the context and event of the starting event
        selected_event = machine_data.iloc[event_index]
        selected_sequence_index = selected_event['Index']
        selected_context_labeled = context[selected_sequence_index]
        selected_Attention = attention[event_index]

        # Get the attention each event in the context. Then place them in descending order. So [(event, attention), ...]
        indexes = [(i, selected_Attention[i].item()) for i in range(len(selected_context_labeled))]
        indexes = sorted(indexes, key=lambda x: x[1], reverse=True)
        
        # Get the list of children nodes for the selected node
        for sel_node in selected_nodes:
            children = getChildren(sel_node, TempNet.edges)
            # for each index in the indexes list. Check if the associated node is in the children list
            for items in indexes:
                found = False
                if items[1] < (1/len(selected_context_labeled)):
                    break
                # get nodes based on the index
                nodes = [node for node in TempNet.techniques if node.code == machine_data.iloc[event_index - 10 + items[0]]['Technique'].split('.')[0]]
                for node in nodes:
                    if node in children:
                        found = True
                        # add the edge to the predicted edges
                        for a,b,_ in TempNet.predicted_edges:
                            if a == sel_node and b == node:
                                found = False
                                break
                        if found:
                            TempNet.predicted_edges.append((node, sel_node, items[1]))
                            break
                if found:
                    event_index = event_index - 10 + items[0]
                    used += 1
                    start_time = machine_data.iloc[event_index]['Date_Time']
                    used, start_time = traverseBehaviorRecursion(TempNet, machine_data, event_index, attention, context, node = node, used=used)
                    used_copy = used
                    return used, start_time
            
        if not found:
            for items in indexes:
                found = False
                if machine_data.iloc[event_index - 10 + items[0]]['Technique'].split('.')[0] == selected_event['Technique'].split('.')[0]:
                    event_index = event_index - 10 + items[0]
                    found = True
                    used += 1
                    break
        if not found:
            return used_copy, start_time
    return used_copy, start_time

def isContinuous(edges):
    node_count = {}
    for edge in edges:
        start, end, _ = edge
        node_count[start] = node_count.get(start, 0) + 1
        node_count[end] = node_count.get(end, 0) + 1

    end_nodes = [node for node, count in node_count.items() if count == 1]

    if len(end_nodes) != 2:
        return False
    else:
        return True
    
def completionRate(edges, path_edges, current_node):
    if len(path_edges) == 0:
        return 0
    # find target node by finding which node is the lowest in the graph (can be multiple)
    target_nodes = []
    for edge in edges:
        if len(target_nodes) == 0:
            target_nodes = [edge[0]]
        elif edge[0].phase < target_nodes[0].phase:
            target_nodes = [edge[0]]
        elif edge[0].phase == target_nodes[0].phase:
            target_nodes.append(edge[0])
    
    # check if one of the target nodes is in the path_edges
    for edge in path_edges:
        if edge[0] in target_nodes:
            return 1
    
    old_length = 9999
    for target in target_nodes:
        path_length = bfs(edges, current_node, target)
        if path_length < old_length and path_length != -1:
            old_length = path_length
        
    if old_length == 9999:
        return 1

    return len(path_edges)/path_length
    

def getLists(BehaviorNet, TempNet):
    # Get the edge list of the BehaviorNet
    BehaviorNet_edges = []
    for edge in BehaviorNet.edges:
        BehaviorNet_edges.append([(edge[0].code, edge[0].phase), (edge[1].code, edge[1].phase)])

    # Get the edge list of the TempNet
    TempNet_edges = []
    for edge in TempNet.edges:
        TempNet_edges.append([(edge[0].code, edge[0].phase), (edge[1].code, edge[1].phase)])

    # get the edge list of the predicted edges
    predicted_edges = []
    for edge in TempNet.predicted_edges:
        predicted_edges.append([(edge[0].code, edge[0].phase), (edge[1].code, edge[1].phase), edge[2]])

    # get the list of nodes in the BehaviorNet
    BehaviorNet_nodes = []
    for node in BehaviorNet.techniques:
        BehaviorNet_nodes.append((node.code, node.phase))
    
    # get the list of nodes in the TempNet
    TempNet_nodes = []
    for node in TempNet.techniques:
        TempNet_nodes.append((node.code, node.phase))

    return [BehaviorNet_nodes, BehaviorNet_edges], [TempNet_nodes, TempNet_edges], predicted_edges

def bfs(edges, start, target):
    visited = set()
    queue = deque([(start, 0)])

    while queue:
        node, length = queue.popleft()

        if node == target:
            return length
        
        if node not in visited:
            visited.add(node)
            for edge in edges:
                src, dest = edge
                if src == node:
                    queue.append((dest, length + 1))
                elif dest == node:
                    queue.append((src, length + 1))

    return -1  # If no path is found