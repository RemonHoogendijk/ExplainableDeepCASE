from deepcase.preprocessing import Preprocessor
from deepcase.context_builder import ContextBuilder
from deepcase.interpreter import Interpreter

import numpy as np
import torch

# Functions
def preprocessData(inputstring, event_length = 10, event_timeout = 86400):
    # Create preprocessor
    preprocessor = Preprocessor(
        length = event_length, # nr. of events in context
        timeout = event_timeout, # Ignore events older than timeout (in seconds)
    )

    # Check if input is csv, txt, or other
    if inputstring.endswith('.csv'):
        context, events, labels, mapping = preprocessor.csv(inputstring)
    elif inputstring.endswith('.txt'):
        context, events, labels, mapping = preprocessor.text(inputstring)
    else:
        raise Exception('File type not supported')
    
    # In case no labels were supplied, set the labels to -1
    if labels is None:
        labels = np.full(events.shape[0], -1, dtype=int)

    # Return the context, events, labels, and mapping
    return context, events, labels, mapping

def contextBuilder(context_train, events_train, input_size = 100, output_size = 100, hidden_size = 128, max_length = 10, epochs = 10, batch_size = 32, learning_rate = 0.01, verbose = True):
    # check if file exists
    try:
        context_builder = ContextBuilder.load('builder.save')
        return context_builder
    except:
        # Create context builder
        context_builder = ContextBuilder(
            input_size = input_size, # nr. of unique events
            output_size = output_size, # nr. of unique contexts (same as input size)
            hidden_size = hidden_size, # nr. of hidden nodes in the hidden layer
            max_length = max_length, # max length of context, should be the same as context set in preprocessor
        )

        context_builder.fit(
            X = context_train, # context
            y = events_train.reshape(-1, 1), # events
            epochs = epochs, # nr. of epochs to train
            batch_size = batch_size, # batch size
            learning_rate = learning_rate, # learning rate
            verbose = verbose, # print progress
        )

        # Save ContextBuilder to file
        context_builder.save('builder.save')
        # Load ContextBuilder from file
        # context_builder = ContextBuilder.load('path/to/file.save')

        # Return the context builder
        return context_builder


def interpreterFit(context_builder, context_train, events_train, features = 100, epsilon = 0.1, min_samples = 5, threshold = 0.2, iterations = 100, batch_size = 1024, verbose = True):
    # Check if file exists
    try:
        interpreter = Interpreter.load('interpreter.save')
        clusters = interpreter.cluster(
            X = context_train, # context to train with
            y = events_train.reshape(-1, 1), # events to train with
            iterations = iterations, # nr. of iteration to use for attention query, in paper this was 100
            batch_size = batch_size, # batch size to use for attention query
            verbose = verbose, # print progress
        )
        return clusters, interpreter
        # return interpreter
    except:
        # Create interpreter
        interpreter = Interpreter(
            context_builder = context_builder, # context builder used to fit data
            features = features, # nr. of features. should be the same as context builder
            eps = epsilon, # epsilon for DBSCAN
            min_samples = min_samples, # min samples for DBSCAN
            threshold = threshold, # threshold for determining if attention from context builder can be used or not
        )

        # Predict anomalies
        clusters = interpreter.cluster(
            X = context_train, # context to train with
            y = events_train.reshape(-1, 1), # events to train with
            iterations = iterations, # nr. of iteration to use for attention query, in paper this was 100
            batch_size = batch_size, # batch size to use for attention query
            verbose = verbose, # print progress
        )

        # Save Interpreter to file
        interpreter.save('interpreter.save')

        # Return the predictions
        return clusters, interpreter

def manualMode(labels_train, context_train, clusters, events_train, interpreter, verbose = True):
    # Create something that picks out a few sequences from each cluster and allows you to evaluate them manually
    # Get all unique clusters
    unique_clusters = np.unique(clusters)
    # For each cluster, pick out a few sequences and evaluate them manually
    print("\tProcessing each cluster...")
    for cluster in unique_clusters:
        # Get all sequences in cluster
        cluster_sequences = context_train[clusters == cluster]

        # Get nr. of sequences in cluster
        nr_sequences = cluster_sequences.shape[0]
        # Get nr. of sequences to evaluate (default 5?)
        nr_sequences_to_evaluate = min(1+(nr_sequences//10), 10)
        # Get indices of sequences to evaluate (randomly)
        indices = np.random.choice(nr_sequences, nr_sequences_to_evaluate, replace=False)
        # Get sequences to evaluate
        sequences_to_evaluate = cluster_sequences[indices]

        # for sequence in sequences_to_evaluate:
        #     print(f'Sequence: {sequence}')
        #     print(f'for event: {events_train[torch.where(torch.all(context_train == sequence, dim=1))[0][0].item()]}')
        #     print(f'with label: {labels_train[torch.where(torch.all(context_train == sequence, dim=1))[0][0].item()]}')
        #     print(f'with cluster: {cluster}')
        #     print("=============================================================")
        #     print("score = -3: Context Builder is not confident enough in the prediction to assign a score")
        #     print("score = -2: Event was not in the training dataset")
        #     print("score = -1: Nearest cluster is too far awap to assign a score")
        #     print("score = 0:  False positive or unimportant event")
        #     print("score = 1:  Low priority event")
        #     print("score = 2:  Medium priority event")
        #     print("score = 3:  High priority event")
        #     print("=============================================================")
        #     user_input = input('What is the score you would give this sequence? (0,1,2,3)? ')
        #     if user_input != "0" and user_input != "1" and user_input != "2" and user_input != "3":
        #         print("Invalid input, setting score to 0")
        #         user_input = 0
        #     labels_train[torch.where(torch.all(context_train == sequence, dim=1))[0][0].item()] = int(user_input)

        # get a random int between 0 and 3 and assign it to the sequence
        for sequence in sequences_to_evaluate:
            for index in torch.where(torch.all(context_train == sequence, dim=1))[0]:
                value = np.random.randint(0, 4)
                labels_train[index.item()] = value

    # Evaluate sequences in manual mode
    print('\tCalculating the score for each cluster...')
    try:
        scores = interpreter.score_clusters(
            scores = labels_train,  # Labels to compute the score as loaded by preprocessor or put your own labels here
            strategy = "max",  # Strategy to compute the score, either "max", "min", or "avg"
            NO_SCORE = -1,  # Any sequence with this score will be ignored in the strategy.
                            # If assigned a cluster, the sequence will inherit the cluster score.
                            # If the sequence is not present in a cluster, it will receive a score of NO_SCORE.
        )
    except:
        print("\tError calculating the score for each cluster. Stoping...")
        exit()

    # Assign scores to clusters in interpreter
    # Note that all sequences should be given a score and each sequence in the same cluster should have the same score
    print('\tAssigning scores to event within clusters...')
    interpreter.score(
        scores = scores, # Scores to assign to clusters
        verbose = verbose, # Print progress
    )

    return interpreter