import numpy as np
from time import time

from sklearn import metrics
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB, MultinomialNB
from sklearn.linear_model import LinearRegression, LogisticRegression
#from sklearn.ensemble import RandomForestRegressor
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import cross_val_predict

import warnings

class ModelsTest:
    def __init__(self, x_data, y_data, test_type, data_used, split):
        self.x_data = x_data
        self.y_data = y_data
        self.test_type = test_type
        if data_used < 1:
            self._resample(data_used)
        if self.test_type == 'split':
            self._resample(split, True)

    def run(self):
        models = [
            ['Decision Tree', DecisionTreeClassifier()],
            ['Gaussian NB', GaussianNB()],
            ['Multinomial NB', MultinomialNB()],
            #['RandomForest', RandomForestRegressor()],
            ['LogRegression', LogisticRegression()],
            ['Nearest Neighbors', KNeighborsClassifier()]
        ]

        print('{:^18} | {:^16} | {:^16} | {:^16}'
              .format('Model', 'Time', 'Accuracy (train)', 'Accuracy (test)'))
        print('----------------------------------------------------------------------------')
        
        for model in models:
            start_time = time()
            acc, acc_test = self.fitMlAlgorithm(model[1])
            total_time = round(time() - start_time, 3)
            print('{:^18} | {:^16} | {:^16} | {:^16}'
                  .format(model[0], total_time, acc, acc_test))

        
            

    def _resample(self, data_used, use_split=False):
        mask = np.random.rand(self.x_data.shape[0]) < data_used
        if not use_split:
            self.x_data = self.x_data[mask]
            self.y_data = self.y_data[mask]
        else:
            self.x_test = self.x_data[~mask]
            self.y_test = self.y_data[~mask]
            self.x_data = self.x_data[mask]
            self.y_data = self.y_data[mask]
        
    
    def fitMlAlgorithm(self, algo):
        # One Pass
        model = algo.fit(self.x_data, self.y_data)
        acc = round(model.score(self.x_data, self.y_data) * 100, 2)

        # Cross Validation
        if self.test_type == 'cv':
            train_pred = cross_val_predict(algo, self.x_data, self.y_data,
                                            cv=10, n_jobs=-1)
            acc_test = round(metrics.accuracy_score(self.y_data, train_pred) * 100, 2)
        # Test/train split
        elif self.test_type == 'split':
            acc_test = round(model.score(self.x_test, self.y_test) * 100, 2)
        
        return acc, acc_test


'''
runTests: call this function to test accuracy of selected models
x_data: Pandas dataframe containing the features to test on
y_data: Pandas dataframe containing the correct classifications for x_data
test_type: (optional) currently defaults to cv (10-fold cross-validation) but can be
    set to split for test/train split
split: (optional) only used if you set test_type to split, value is fraction to
    put into training dataset
data_used: (optional) defaults to using all data but to speed things up with small
    drop in accuracy can use a fraction of the set only
'''
def runTests(x_data, y_data, test_type='cv', data_used=1, split=0.7):
    warnings.filterwarnings('ignore')
    mt = ModelsTest(x_data, y_data, test_type, data_used, split)
    mt.run()
