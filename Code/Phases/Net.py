from pyvis.network import Network
import networkx as nx
import matplotlib.pyplot as plt

Mitre_mapping = {
    None: 0,
    'None': 0,
    'Reconnaissance': 1,
    'Discovery': 1,
    'Initial Access': 2,
    'Credential Access': 2,
    'Execution': 3,
    'Persistence': 3,
    'Privilege Escalation': 3,
    'Lateral Movement': 3,
    'Defense Evasion': 3,
    'Command and Control': 4,
    'Collection': 4,
    'Exfiltration': 5,
    'Impact': 5,
}

class Alert:
    def __init__(self, date_time, message, protocol, source, source_port, dest, dest_port, tactics, index):
        self.date_time = date_time
        self.message = message
        self.protocol = protocol
        self.source = source
        self.source_port = source_port
        self.dest = dest
        self.dest_port = dest_port
        self.phase = 0
        self.weight = 1
        self.children = []
        self.tactics = tactics
        self.code = ""
        self.codeName = ""
        self.index = index
    
    def setCode(self, code):
        self.code = code

    def setCodeName(self, codeName):
        self.codeName = codeName

    def addWeight(self):
        self.weight += 1


    def __str__(self):
        return f"Date_Time: {self.date_time}\nMessage: {self.message}\nProtocol: {self.protocol}\nSource: {self.source}\nSource Port: {self.source_port}\nDestination: {self.dest}\nDestination Port: {self.dest_port}"

class Technique:
    def __init__(self, code, name, phase):
        self.code = code
        self.phase = phase
        self.name = name
        self.weight = 1
        self.alerts = []
        self.start = None
        self.end = None

    def addWeight(self):
        self.weight += 1

    def __str__(self):
        return f"Message: {self.message}\nPhase: {self.phase}\nWeight: {self.weight}"
    
    def setStartandEnd(self):
        for alert in self.alerts:
            if self.start == None or alert.date_time < self.start:
                self.start = alert.date_time
            if self.end == None or alert.date_time > self.end:
                self.end = alert.date_time
    
    def resetEnd(self, time):
        self.end = None
        for alert in self.alerts:
            if self.end == None or (alert.date_time > self.end and alert.date_time <= time):
                self.end = alert.date_time

    def copy(self):
        newTechnique = Technique(self.code, self.name, self.phase)
        newTechnique.weight = self.weight
        newTechnique.alerts = self.alerts.copy()
        newTechnique.start = self.start
        newTechnique.end = self.end
        return newTechnique

class Net:
    def __init__(self):
        self.techniques = []
        self.edges = []
        self.enabled = False
        self.predicted_edges = []

    def checkAlert(self, alert):
        if alert.code == 'None' or alert.codeName == 'None':
            return
        for tactic in alert.tactics:
            phase = Mitre_mapping[tactic]
            if phase == 0:
                return
            # check if the technique is already in the list, if it is, add the alert to that technique
            addNew = True
            for technique in self.techniques:
                if (technique.code.split('.')[0] == alert.code.split('.')[0]) and technique.phase == phase:  # By using the split we ignore the sub-techniques
                    technique.alerts.append(alert)
                    addNew = False
                # if it is not, create a new technique and add the alert to that technique
            if addNew:
                new_technique = Technique(alert.code.split('.')[0], alert.codeName, phase)
                new_technique.alerts.append(alert)
                self.techniques.append(new_technique)
            
    
    def checkTimes(self):
        for technique in self.techniques:
            technique.setStartandEnd() 

    def createEdges(self):
        for i in range(len(self.techniques)):
            for j in range(len(self.techniques)):
                if self.techniques[i].start < self.techniques[j].end and i != j:
                    self.edges.append((self.techniques[i], self.techniques[j]))
        
        transitive_reduction = self.edges.copy()
        for i, j in self.edges:
            for k in self.techniques:
                if (i, k) in self.edges and (k, j) in self.edges and k.phase != i.phase and k.phase != j.phase: 
                    transitive_reduction = [edge for edge in transitive_reduction if edge != (i, j)]
                    break
        
        self.edges = transitive_reduction
            
    
    def _lenEdges_(self):
        return len(self.edges)
    
    def copy(self):
        newNet = Net()
        newNet.techniques = [technique.copy() for technique in self.techniques]
        newNet.edges = [(edge[0].copy(), edge[1].copy()) for edge in self.edges]
        newNet.predicted_edges = []
        return newNet
    
    def getNode(self, code, phase):
        results = []
        for technique in self.techniques:
            if technique.code == code:
                results.append(technique)
        if len(results) == 0:
            return None
        elif len(results) == 1:
            return results[0]
        else:
            x = lambda a,b: a if a.phase > b.phase and a.phase < phase else b
            return x(results[0], results[1])
    
    def createGraph(self):
        if len(self.techniques) <= 1:
            print("\tNot enough techniques to create a graph...")
            return
        # self.checkTimes()
        # self.createEdges()
        print("\tCreating Graph from Net...")
        export = nx.DiGraph()

        net = Network(directed =True)

        colors = {
            1: 'lightgreen',
            2: 'yellow',
            3: 'orange',
            4: 'red',
            5: 'darkred'
        }

        for technique in self.techniques:
            net.add_node(str(technique.code) + str(technique.phase), technique.code + ' ' + technique.name, color=colors[technique.phase])

        edgelist = [(item[0], item[1]) for item in self.predicted_edges]
        for edge in self.edges:
            if (edge[0], edge[1]) in edgelist:
                for edge2 in self.predicted_edges:
                    if edge2[0] == edge[0] and edge2[1] == edge[1]:
                        net.add_edge(str(edge2[0].code) + str(edge2[0].phase), str(edge2[1].code) + str(edge2[1].phase), color='blue', value=10*edge2[2], physics=True)
            else:
                net.add_edge(str(edge[0].code) + str(edge[0].phase), str(edge[1].code) + str(edge[1].phase), value=0.1, color='lightgrey')

        # for edge in self.predicted_edges:
        #     net.add_edge(str(edge[0].code) + str(edge[0].phase), str(edge[1].code) + str(edge[1].phase), color='blue', value=10*edge[2], physics=True)

        # for edge in self.predicted_edges:
        #     if (edge[0], edge[1]) not in self.edges:
        #         net.add_edge(str(edge[0].code) + str(edge[0].phase), str(edge[1].code) + str(edge[1].phase), color='blue', value=(edge[1].weight/2)+1, physics=True)

        net.force_atlas_2based(gravity=-50, central_gravity=0.01, spring_length=100, spring_strength=0.08, damping=0.4, overlap=0)

        # Iterate over nodes and add them to NetworkX graph
        for i in net.nodes:
            export.add_node(i["id"], label=i["label"], color=i['color'])

        # Iterate over edges and add them to NetworkX graph
        for i in net.edges:
            export.add_edge(i["from"], i["to"], weight=i['value'], colors=i['color'])

        # Save NetworkX graph
        nx.write_graphml(export, "exported_graph.graphml")

        net.show('nodes.html', notebook=False)


class SecondGenNet:

    def __init__(self) -> None:
        self.unique_alerts = []
        self.alerts = {}
        self.edges = []
        self.count = 0

    def addEdge(self, root, alert):
        if (root, alert) in self.edges:
            return
        self.edges.append((root, alert))

    def checkAlert(self, alert):
        if alert.phase == 0:
            return
        if len(self.alerts) == 0:
            self.alerts[alert] = alert
            self.unique_alerts.append(alert)
        else:
            for item in self.unique_alerts:
                if item.message == alert.message and item.source == alert.source and item.dest == alert.dest:
                    item.addWeight()
                    self.count += 1
                    return
            prev_len = len(self.unique_alerts)
            prev_count = self.count
            temp = self.alerts.copy()
            for root in temp:
                if root.phase >= alert.phase:
                    continue
                self.recursive(root, alert)    
            if prev_len == len(self.unique_alerts) and prev_count == self.count:
                self.alerts[alert] = alert
                self.unique_alerts.append(alert)
                self.count += 1

    def recursive(self, root, alert):
        if root.phase == alert.phase:
            return
        if len(root.children) == 0 and root.phase < alert.phase:
            root.children.append(alert)
            self.addEdge(root, alert)
            self.unique_alerts.append(alert)
            return
        if len(root.children) == 0 and root.phase > alert.phase:
            return
        else:
            add_now = True
            for child in root.children:
                if child.phase < alert.phase:
                    add_now = False
                    self.recursive(child, alert)
            if add_now:
                root.children.append(alert)
                self.addEdge(root, alert)
                

    def _lenEdges_(self):
        return len(self.edges)

    def createGraph(self):
        net = Network(directed =True)

        colors = {
            1: 'lightgreen',
            2: 'yellow',
            3: 'orange',
            4: 'red',
            5: 'darkred'
        }

        for alert in self.unique_alerts:
            net.add_node(str(alert.date_time) + alert.message, str(alert.date_time) + alert.message, color=colors[alert.phase])

        for edge in self.edges:
            net.add_edge(str(edge[0].date_time) + edge[0].message, str(edge[1].date_time) + edge[1].message, value=(edge[1].weight/2)+1)

        net.force_atlas_2based(gravity=-50, central_gravity=0.01, spring_length=100, spring_strength=0.08, damping=0.4, overlap=0)
        net.show('nodes.html', notebook=False)
    

class OldNet:
    def __init__(self):
        self.phases = {1: [], 2: [], 3: [], 4: [], 5: []}
        self.edges = []

    def checkAlert(self, alert):
        # Check alerts current phase
        # add alert to current phase
        found = False
        if alert.phase == 0:
            return
        for old in self.phases[alert.phase]:
            if old.message == alert.message \
                and old.source == alert.source \
                and old.dest == alert.dest:
                old.addWeight()
                found = True
        if not found:
            self.phases[alert.phase].append(alert)
            # check which of the previous phases has an alert
            # if there are alerts in previous phases
            if alert.phase > 1:
                for i in range(alert.phase - 1, 0, -1):
                    if len(self.phases[i]) > 0:
                        # add edge between the current allert and all alerts in the previous phase
                        for prev_alert in self.phases[i]:
                            if prev_alert.phase != alert.phase:
                                self.edges.append((prev_alert, alert))
                        break

    def _lenEdges_(self):
        return len(self.edges)
    
    def createGraph(self):
        net = Network(directed =True)

        colors = {
            1: 'lightgreen',
            2: 'yellow',
            3: 'orange',
            4: 'red',
            5: 'darkred'
        }

        for phase in self.phases:
            for alert in self.phases[phase]:
                net.add_node(str(alert.date_time) + alert.message, str(alert.date_time) + alert.message, color=colors[phase])

        for edge in self.edges:
            net.add_edge(str(edge[0].date_time) + edge[0].message, str(edge[1].date_time) + edge[1].message, value=(edge[1].weight/2)+1)

        net.force_atlas_2based(gravity=-50, central_gravity=0.01, spring_length=100, spring_strength=0.08, damping=0.4, overlap=0)
        net.show('nodes.html', notebook=False)

    # def createGraph(self):
    #     G = nx.DiGraph()
    #     colors = {
    #         1: 'lightgreen',
    #         2: 'yellow',
    #         3: 'orange',
    #         4: 'red',
    #         5: 'darkred'
    #     }

    #     color = []
    #     for phase in self.phases:
    #         for alert in self.phases[phase]:
    #             G.add_node(str(alert.date_time) + alert.message)
    #             color.append(colors[phase])

    #     for edge in self.edges:
    #         G.add_edge(str(edge[0].date_time) + edge[0].message, str(edge[1].date_time) + edge[1].message, weight=(edge[1].weight/2)+1)

    #     nx.draw(G, with_labels=True, node_color=color, node_size=3000, edge_color='black', linewidths=1, font_size=10, font_color='black', font_weight='bold', alpha=0.7)
    #     plt.show()